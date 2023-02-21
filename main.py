from PySide6 import QtWidgets, QtGui, QtCore

import sys
import os
import traceback
import typing

from util import get_decompile_data
from decomp import Decomp, DecompStep
from ui import GraphView

class MainWindow(QtWidgets.QMainWindow):
    decomp_dbg_suffix: str = os.path.join(
        "Ghidra", "Features", "Decompiler", "src", "decompile", "cpp", "decomp_dbg"
    )
    load_data_done: QtCore.Signal = QtCore.Signal(Decomp, str)

    xml_func_name: str = ""
    xml_path: str = ""
    ghidra_dir: str = ""

    decomp: typing.Optional[Decomp] = None
    graph_view: GraphView
    decomp_step: int = 0

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

        # Create main widget
        main_widget = QtWidgets.QWidget()
        self.setCentralWidget(main_widget)

        self.list_widget = QtWidgets.QListWidget(main_widget)
        self.list_widget.addItem("None")
        self.list_widget.currentRowChanged.connect(self.handle_list_change)

        self.text_edit = QtWidgets.QTextEdit(main_widget)
        self.text_edit.setReadOnly(True)

        self.graph_view = GraphView(None)

        # Setup things for threading
        self.thread_manager = QtCore.QThreadPool(self)
        self.load_data_done.connect(self._process_load_decomp_data)

        L = QtWidgets.QGridLayout(self)
        L.addWidget(self.text_edit, 0, 0)
        L.addWidget(self.graph_view, 0, 1, 2, 1)
        L.addWidget(self.list_widget, 1, 0)

        L.setColumnStretch(0, 1)
        L.setColumnStretch(1, 3)
        L.setRowStretch(0, 1)
        L.setRowStretch(1, 3)

        main_widget.setLayout(L)

    def _handle_set_xml_file(self):
        """
        Handles the 'Set XML File' menu action being clicked.
        """
        file_name, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Choose an XML file")

        if file_name == "":  # No XML file was selected
            return

        self.xml_path = file_name

        # TODO: This is a hacky way to extract the function name that doesn't
        # work when the specified xml file is generated from a function that is
        # part of a class.
        with open(self.xml_path, "r", encoding="utf-8") as f:
            line = f.readline()

        assert line.startswith('<xml_savefile name="')

        self.xml_func_name = line.split('"')[1]
        self.load_decomp_data()

    def _handle_set_ghidra_dir(self):

        while True:
            ghidra_dir = QtWidgets.QFileDialog.getExistingDirectory(
                self, "Choose the Ghidra Installation folder"
            )

            if ghidra_dir == "":  # No folder was selected
                return

            debug_path = os.path.join(ghidra_dir, self.decomp_dbg_suffix)

            if os.path.isfile(debug_path):
                break

        self.ghidra_dir = ghidra_dir
        self.decomp_dbg_path = debug_path

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

        self.text_edit.setPlainText(initial_pcode)

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

    def load_decomp_data(self):
        if self.ghidra_dir is None:
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
        if self.decomp is None:
            # Happens when no XML is loaded
            return

        self.graph_view.set_graph(self.decomp.get_state(new_index).get_graph())
        if new_index != 0:
            self.text_edit.setPlainText(str(self.decomp.get_step(new_index - 1)))


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)

    mw = MainWindow()
    mw.show()

    exitcodesys = app.exec()
    app.deleteLater()

    sys.exit(exitcodesys)
