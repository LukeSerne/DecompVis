from PySide6 import QtWidgets, QtGui, QtCore

import sys
import os
import traceback
import typing
import xml.etree.ElementTree
import argparse
import pathlib
import difflib

from util import get_decompile_data, make_xpath_string, colourise_diff, html_escape
from decomp import Decomp
from ui import GraphView, ZoomSliderWidget, SearchWidget


class MainWindow(QtWidgets.QMainWindow):
    decomp_dbg_suffix: str = os.path.join(
        "Ghidra", "Features", "Decompiler", "src", "decompile", "cpp", "decomp_dbg"
    )
    load_data_done: QtCore.Signal = QtCore.Signal(Decomp)
    zoom_levels: tuple[float] = (
        0.1, 0.15, 0.2, 0.25, 0.3, 0.35, 0.4, 0.45, 0.5, 0.55, 0.6, 0.65, 0.7,
        0.75, 0.85, 0.9, 0.95, 1.0, 1.25, 1.5, 1.75, 2.0, 2.5, 3.0,
    )

    xml_func_name: str = ""
    xml_path: str = ""
    ghidra_dir: str = ""
    decomp_dbg_path: str = ""
    decomp: typing.Optional[Decomp] = None
    settings: QtCore.QSettings
    zoom_idx: int = zoom_levels.index(1.0)

    graph_view: GraphView
    list_widget: QtWidgets.QListWidget
    text_edit: QtWidgets.QTextEdit
    thread_manager: QtCore.QThreadPool

    def __init__(self, extra_paths = [], default_xml: typing.Optional[pathlib.Path] = None):
        super().__init__()

        self.extra_paths = extra_paths

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

        # Create main widgets
        self.graph_view = GraphView(None, self)
        self.setCentralWidget(self.graph_view)

        self.list_widget = QtWidgets.QListWidget(self)
        self.list_widget.currentRowChanged.connect(self.handle_list_change)
        list_dock_widget = QtWidgets.QDockWidget("P-CODE Stages", self)
        list_dock_widget.setWidget(self.list_widget)

        self.text_edit = QtWidgets.QTextEdit(self)
        self.text_edit.setReadOnly(True)
        self.text_edit.setLineWrapMode(QtWidgets.QTextEdit.LineWrapMode.NoWrap)

        text_dock_widget = QtWidgets.QDockWidget("Information", self)
        text_dock_widget.setWidget(self.text_edit)

        self.search_widget = SearchWidget(self.graph_view, self)
        search_dock_widget = QtWidgets.QDockWidget("Search Node", self)
        search_dock_widget.setWidget(self.search_widget)

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

        self.addDockWidget(QtCore.Qt.DockWidgetArea.LeftDockWidgetArea, list_dock_widget)
        self.addDockWidget(QtCore.Qt.DockWidgetArea.LeftDockWidgetArea, text_dock_widget)
        self.addDockWidget(QtCore.Qt.DockWidgetArea.LeftDockWidgetArea, search_dock_widget)

        # Load first xml if set
        if default_xml is not None:
            self._parse_xml_file(default_xml)

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

        self._parse_xml_file(file_name)

    def _parse_xml_file(self, file_name):
        """
        Loads and parses the XML file the 'file_name' argument refers to. Fianally,
        it feeds the XML into decomp_dbg.
        """
        self.xml_path = file_name

        xml_data = xml.etree.ElementTree.parse(self.xml_path)
        xml_root = xml_data.getroot()

        # Find the range for which we have bytes
        bytechunks = xml_root.findall("./binaryimage/bytechunk")
        if not bytechunks:
            raise ValueError(f"Did not find 'bytechunk' elements in the provided XML!")

        function_names = []
        for bytechunk in bytechunks:
            bytechunk_space = make_xpath_string(bytechunk.get("space"))

            bytechunk_start = int(bytechunk.get("offset"), 16)
            # Assuming the bytes are stored in hexadecimal, the number of bytes
            # is the number of non-whitespace characers divided by 2.
            bytechunk_size = len(bytechunk.text.replace(" ", "").replace("\n", "")) // 2
            bytechunk_range = range(bytechunk_start, bytechunk_start + bytechunk_size)

            # Find the names of all functions defined in the XML file, and filter
            # out those whose offsets are not inside the chunk for which we have
            # bytes
            for scope in xml_root.findall("./save_state/db/scope"):
                scope_name = scope.get("name")

                for function in scope.findall("./symbollist/mapsym/function"):
                    # Do we have the bytes for this function?
                    addr_def = function.find(f"./addr[@space={bytechunk_space}]")
                    if addr_def is None or int(addr_def.get("offset"), 16) not in bytechunk_range:
                        continue

                    # Yes - add the fully qualified name to the list of function
                    # names.
                    func_name = function.get('name')

                    if "::" in func_name:
                        raise ValueError(f"Function names containing '::' are not supported by the decompiler ({func_name!r})")

                    function_names.append(f"{scope_name}::{func_name}")

        if not function_names:
            raise ValueError("No function definition found in XML file")

        if len(function_names) > 1:
            # TODO: Handle this case more cleanly - for example by allowing the
            # user to choose one of the functions.
            print("Found multiple functions - picking first one")
            print(function_names)

        self.xml_func_name = function_names[0]
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
            pcodes = get_decompile_data(
                self.decomp_dbg_path, self.ghidra_dir, self.xml_path, self.xml_func_name, self.extra_paths
            )

            decomp = Decomp(pcodes)
        except:
            print("Exception while loading the Decompiler data!")
            print(traceback.format_exc())
            if decomp is None:
                print("Cancelling loading!")
                return

        self.load_data_done.emit(decomp)

    def _process_load_decomp_data(self, decomp: Decomp):
        self.decomp = decomp

        self.list_widget.clear()
        self.list_widget.addItems([
            f"{i}: {rule_name}"
            for i, rule_name in enumerate(self.decomp.get_rule_names())
        ])

        self.list_widget.setEnabled(True)
        self.text_edit.setEnabled(True)
        self.graph_view.setEnabled(True)
        self.search_widget.enable()

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
        state = self.decomp.get_state(new_index)

        self.graph_view.set_graph(state.get_graph())

        full_text = ""

        if new_index != 0:
            prev_state = self.decomp.get_state(new_index - 1)
            full_text = "<h1>Delta</h1>" + colourise_diff(difflib.ndiff(prev_state._pcode.split("\n"), state._pcode.split("\n")))

        full_text += "<h1>New State</h1><div><tt>" + html_escape(state._pcode).strip("\n").replace("\n", "<br/>") + "</tt></div>"
        self.text_edit.setText(full_text)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('xmlfile', nargs='?', help='Specify the path to an XML file to automatically load it', type=lambda p: pathlib.Path(p).absolute())
    parser.add_argument('-s', '--extra-paths', nargs='+', help='Define extra paths to search for language definitions (.ldefs)', required=False, default=[])
    args = parser.parse_args()

    app = QtWidgets.QApplication(sys.argv)

    mw = MainWindow(args.extra_paths, args.xmlfile)
    mw.show()

    exitcodesys = app.exec()
    app.deleteLater()

    sys.exit(exitcodesys)
