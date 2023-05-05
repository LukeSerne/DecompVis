from PySide6 import QtWidgets, QtGui, QtCore

import sys
import os
import traceback
import typing
import xml.etree.ElementTree

from util import get_decompile_data
from decomp import Decomp, DecompStep
from ui import GraphView, ZoomSliderWidget


class MainWindow(QtWidgets.QMainWindow):
    decomp_dbg_suffix: str = os.path.join(
        "Ghidra", "Features", "Decompiler", "src", "decompile", "cpp", "decomp_dbg"
    )
    load_data_done: QtCore.Signal = QtCore.Signal(Decomp, str)
    zoom_levels: tuple[float] = (
        0.1, 0.15, 0.2, 0.25, 0.3, 0.35, 0.4, 0.45, 0.5, 0.55, 0.6, 0.65, 0.7,
        0.75, 0.85, 0.9, 0.95, 1.0, 1.25, 1.5, 1.75, 2.0, 2.5, 3.0,
    )

    xml_func_name: str = ""
    xml_path: str = ""
    ghidra_dir: str = ""
    decomp_dbg_path: str = ""
    decomp: typing.Optional[Decomp] = None
    initial_pcode: str = ""
    settings: QtCore.QSettings
    zoom_idx: int = zoom_levels.index(1.0)

    graph_view: GraphView
    list_widget: QtWidgets.QListWidget
    text_edit: QtWidgets.QTextEdit
    thread_manager: QtCore.QThreadPool

    def __init__(self):
        super().__init__()

        self.setWindowTitle("DecompVis")

        # Populate menu bar
        menu_bar = self.menuBar()
        file_menu = menu_bar.addMenu("&File")

        load_xml_act = QtGui.QAction("Load XML file", self)
        load_xml_act.triggered.connect(self._handle_set_xml_file)
        set_ghidra_dir_act = QtGui.QAction("Set Ghidra folder", self)
        set_ghidra_dir_act.triggered.connect(self._handle_set_ghidra_dir)

        file_menu.addAction(load_xml_act)
        file_menu.addAction(set_ghidra_dir_act)

        view_menu = menu_bar.addMenu("&View")

        self.zoom_in_act = QtGui.QAction("Zoom In", self)
        self.zoom_in_act.triggered.connect(self._handle_zoom_in)
        self.zoom_out_act = QtGui.QAction("Zoom Out", self)
        self.zoom_out_act.triggered.connect(self._handle_zoom_out)

        view_menu.addAction(self.zoom_in_act)
        view_menu.addAction(self.zoom_out_act)

        # Create main widget
        main_widget = QtWidgets.QWidget()
        self.setCentralWidget(main_widget)

        self.list_widget = QtWidgets.QListWidget(main_widget)
        self.list_widget.currentRowChanged.connect(self.handle_list_change)

        self.text_edit = QtWidgets.QTextEdit(main_widget)
        self.text_edit.setReadOnly(True)

        self.graph_view = GraphView(None, self)

        # Add a zoom slider to the status bar
        self.zoom_slider = ZoomSliderWidget(len(self.zoom_levels), self.zoom_levels.index(1.0), self)
        self.statusBar().addPermanentWidget(self.zoom_slider)

        # Setup things for threading
        self.thread_manager = QtCore.QThreadPool(self)
        self.load_data_done.connect(self._process_load_decomp_data)

        # Initialise settings ini, and load the ghidra dir
        self.settings = QtCore.QSettings("settings.ini", QtCore.QSettings.IniFormat)
        dir_value = self.settings.value("ghidra_dir")
        if dir_value is not None and not self._try_set_ghidra_dir(dir_value):
            # dir is invalid, reset ini
            self.settings.setValue("ghidra_dir", self.ghidra_dir)

        L = QtWidgets.QGridLayout(main_widget)
        L.addWidget(self.text_edit, 0, 0)
        L.addWidget(self.graph_view, 0, 1, 2, 1)
        L.addWidget(self.list_widget, 1, 0)

        L.setColumnStretch(0, 1)
        L.setColumnStretch(1, 3)
        L.setRowStretch(0, 1)
        L.setRowStretch(1, 3)

    def _try_set_ghidra_dir(self, ghidra_dir: str) -> bool:
        """
        Try to set the Ghidra folder. If this fails (because the folder does
        not exist or because it does not contain the decomp_dbg executable), False
        is returned. Otherwise, the 'ghidra_dir' and 'decomp_dbg_path' variables
        are set and True is returned.
        """
        debug_path = os.path.join(ghidra_dir, self.decomp_dbg_suffix)

        if not os.path.isfile(debug_path):  # invalid path
            return False

        self.ghidra_dir = ghidra_dir
        self.decomp_dbg_path = debug_path

        self.settings.setValue("ghidra_dir", self.ghidra_dir)

        return True

    def _handle_set_xml_file(self):
        """
        Handles the 'Set XML File' menu action being clicked.
        """
        file_name, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Choose an XML file")

        if file_name == "":  # No XML file was selected
            return

        self.xml_path = file_name

        xml_data = xml.etree.ElementTree.parse(self.xml_path)
        xml_root = xml_data.getroot()

        func_name = xml_root.get("name")
        if func_name is None:
            raise ValueError("No function name")

        if "::" in func_name:
            raise ValueError(f"Function names containing '::' are not supported by the decompiler ({func_name!r})")

        for scope in xml_root.findall("./save_state/db/scope"):
            if scope.find(f"./symbollist/mapsym/function[@name={func_name!r}]") is None:
                continue

            # found the function
            scope_name = scope.get("name")
            break
        else:
            raise ValueError(f"No function definition found for function {func_name!r}")

        if scope_name is None:
            raise ValueError(f"Scope containing function has no name attribute")

        if scope_name != "":
            func_name = f"{scope_name}::{func_name}"

        self.xml_func_name = func_name
        self.load_decomp_data()

    def _handle_set_ghidra_dir(self):

        while True:
            ghidra_dir = QtWidgets.QFileDialog.getExistingDirectory(
                self, "Choose the Ghidra Installation folder"
            )

            if ghidra_dir == "":  # No folder was selected
                return

            if self._try_set_ghidra_dir(ghidra_dir):
                return

    def _handle_zoom_in(self, cursor_is_center: bool = False):
        if self.zoom_idx == len(self.zoom_levels) - 1:  # already fully zoomed in
            return

        self._handle_update_zoom(self.zoom_idx + 1, cursor_is_center)

    def _handle_zoom_out(self, cursor_is_center: bool = False):
        if self.zoom_idx == 0:  # already fully zoomed out
            return

        self._handle_update_zoom(self.zoom_idx - 1, cursor_is_center)

    def _handle_update_zoom(self, new_zoom_idx: int, cursor_is_center: bool = False):
        """
        Updates the graph view to have the correct zoom corresponding to
        'new_zoom_idx'. Also enables and disables the menu actions accordingly.
        This function assumes 'new_zoom_idx' is a valid index in
        MainWindow.zoom_levels.
        """
        self.zoom_idx = new_zoom_idx

        self.graph_view.set_zoom(self.zoom_levels[new_zoom_idx], cursor_is_center=cursor_is_center)
        self.zoom_in_act.setEnabled(new_zoom_idx != len(self.zoom_levels) - 1)
        self.zoom_out_act.setEnabled(new_zoom_idx != 0)
        self.zoom_slider.set_zoom_level(new_zoom_idx)

    def _do_load_decomp_data(self):

        decomp = None

        try:
            initial_pcode, data = get_decompile_data(
                self.decomp_dbg_path, self.ghidra_dir, self.xml_path, self.xml_func_name
            )

            decomp = Decomp(initial_pcode)
            for i, rule in enumerate(data):
                decomp.add_step(DecompStep(rule))
        except:
            print("Exception while loading the Decompiler data!")
            print(traceback.format_exc())
            if decomp is None:
                print("Cancelling loading!")
                return

        self.load_data_done.emit(decomp, initial_pcode.decode("utf-8"))

    def _process_load_decomp_data(self, decomp: Decomp, initial_pcode: str):
        self.decomp = decomp
        self.initial_pcode = initial_pcode

        self.list_widget.clear()
        self.list_widget.addItems(
            ["Raw P-CODE"]
            + [
                self.decomp.get_step(i).get_short_desc()
                for i in range(self.decomp.get_num_steps())
            ]
        )

        self.list_widget.setEnabled(True)
        self.text_edit.setEnabled(True)
        self.graph_view.setEnabled(True)

        self._handle_update_zoom(self.zoom_levels.index(1.0))
        self.handle_list_change(0)

    def load_decomp_data(self):
        if self.ghidra_dir == "":
            # No Ghidra dir selected - don't load anything
            return

        self.thread_manager.start(self._do_load_decomp_data)

        # Disable some UI things to indicate we're loading
        self.list_widget.setEnabled(False)
        self.text_edit.setEnabled(False)
        self.graph_view.setEnabled(False)

    def handle_list_change(self, new_index):
        """
        Handles the selected entry in the list changing
        """
        self.graph_view.set_graph(self.decomp.get_state(new_index).get_graph())

        if new_index == 0:
            self.text_edit.setPlainText(self.initial_pcode)
        else:
            self.text_edit.setPlainText(str(self.decomp.get_step(new_index - 1)))


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)

    mw = MainWindow()
    mw.show()

    exitcodesys = app.exec()
    app.deleteLater()

    sys.exit(exitcodesys)
