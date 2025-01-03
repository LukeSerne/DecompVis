from PySide6.QtCore import QLineF, QPointF, QRectF, Qt, QVariantAnimation
from PySide6.QtGui import (
    QBrush,
    QColor,
    QPainter,
    QPen,
    QPolygonF,
    QFontMetricsF,
    QFont,
    QPainterPath,
    QTransform,
)
from PySide6.QtWidgets import (
    QDockWidget,
    QGraphicsItem,
    QGraphicsObject,
    QGraphicsScene,
    QGraphicsView,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSlider,
    QStyleOptionGraphicsItem,
    QTabWidget,
    QTextEdit,
    QWidget,
)
import networkx

import math
import typing
from collections.abc import Iterator

from util import Operation, layout_algorithm


class Node(QGraphicsObject):

    """A QGraphicsItem representing node in a graph"""

    COLORS: dict[str, QColor] = {
        "brown": QColor("#9E5700"),
        "green": QColor("#5AD469"),
        "red": QColor("#E31E1B"),
        "blue": QColor("#2B42E3"),
        "yellow": QColor("#D2E31B"),
        "gray": QColor("#777777"),
    }

    COLOR_NAMES: list[str] = [
        "brown", "green", "red", "blue", "yellow", "gray"
    ]

    _name: str
    _edges: list["Edge"]
    _color_name: str
    _color: QColor
    _bg_brush: QBrush
    _border_pen: QPen
    _is_selected: bool
    _rect: QRectF

    def __init__(self, item, parent=None):
        """Node constructor

        Args:
            item: Item the node represents
        """
        super().__init__(parent)

        self._name = item.get_node_name()
        self._color_name = item.get_color_name()

        self._edges = []
        self._color = self.COLORS[self._color_name]
        self._is_selected = False
        self._bg_brush = QBrush(self._color)
        self._border_pen = QPen(
            self._color.darker(), 2, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin
        )
        self._text_pen = QPen(QColor(
            "white" if self._color_name in {"brown", "gray"} else "black"
        ))

        # Calculate bounding rect by adding a 10 pixel margin around the name
        name_rect = QFontMetricsF(QFont()).boundingRect(self._name)
        self._rect = QRectF(0, 0, name_rect.width() + 10, name_rect.height() + 10)

        self.setFlags(
            QGraphicsItem.ItemIsMovable | QGraphicsItem.ItemSendsGeometryChanges
        )
        self.setCacheMode(QGraphicsItem.DeviceCoordinateCache)

        tooltip_text = item.get_tooltip_text()
        if tooltip_text is not None:
            self.setToolTip(tooltip_text)

    def add_edge(self, edge: "Edge"):
        """Add an edge to this node"""
        self._edges.append(edge)

    def mousePressEvent(self, ev):
        super().mousePressEvent(ev)

        # Change the colour when the node is right-clicked, highlight the node
        # when middle-clicked.
        if ev.button() == Qt.RightButton:
            color_idx = self.COLOR_NAMES.index(self._color_name)
            self._color_name = self.COLOR_NAMES[(color_idx + 1) % len(self.COLOR_NAMES)]
            self._color = self.COLORS[self._color_name]
            self._bg_brush = QBrush(self._color)
            self._text_pen = QPen(QColor(
                "white" if self._color_name in {"brown", "gray"} else "black"
            ))

        elif ev.button() == Qt.MiddleButton:
            self._is_selected = not self._is_selected

        else:
            return

        border_color = self._color.lighter() if self._is_selected else self._color.darker()
        self._border_pen = QPen(
            border_color, 2, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin
        )
        self.update()

    def boundingRect(self) -> QRectF:
        """Override from QGraphicsItem

        Returns:
            QRect: Return node bounding rect
        """
        return self._rect

    def shape(self) -> QPainterPath:
        path = QPainterPath()
        path.addRoundedRect(self.boundingRect(), 5, 5)
        return path

    def paint(self, painter: QPainter, option: QStyleOptionGraphicsItem, widget: QWidget = None):
        """Override from QGraphicsItem

        Draw node

        Args:
            painter (QPainter)
            option (QStyleOptionGraphicsItem)
        """
        bound_rect = self.boundingRect()

        painter.setRenderHints(QPainter.Antialiasing)
        painter.setPen(self._border_pen)
        painter.setBrush(self._bg_brush)
        painter.drawRoundedRect(bound_rect, 5, 5)
        painter.setPen(self._text_pen)
        painter.drawText(bound_rect, Qt.AlignCenter, self._name)

    def itemChange(self, change: QGraphicsItem.GraphicsItemChange, value):
        """Adjusts all edges when the item is moved"""
        if change == QGraphicsItem.ItemPositionHasChanged:
            for edge in self._edges:
                edge.adjust()

        return super().itemChange(change, value)

    def highlight(self):
        self._og_bg_brush = self._bg_brush
        animation = QVariantAnimation(self)
        animation.setStartValue(0)
        animation.setEndValue(2 * 255)
        animation.setDuration(1000)
        animation.setLoopCount(2)
        animation.valueChanged.connect(self.invertedBrush)
        animation.start()

    def invertedBrush(self, animation_step: int):
        if animation_step == 2*255:  # done
            self._bg_brush = self._og_bg_brush
        else:
            if animation_step >= 255:
                animation_step = 2*255 - animation_step

            self._bg_brush = QBrush(QColor(animation_step - self._og_bg_brush.color().red(), animation_step - self._og_bg_brush.color().green(), animation_step - self._og_bg_brush.color().blue()))
        self.update()


class Edge(QGraphicsItem):
    def __init__(self, source: Node, dest: Node, dest_index: int, dest_num_inputs: int, is_dotted: bool, parent: QGraphicsItem = None):
        super().__init__(parent)
        self._source = source
        self._dest = dest
        self._dest_index = dest_index
        self._dest_num_inputs = dest_num_inputs
        self._is_dotted = is_dotted

        self._thickness = 2
        self._color = '#2B42E3' if self._is_dotted else '#2BB53C'
        self._arrow_size = 15

        self._source.add_edge(self)
        self._dest.add_edge(self)

        self._line = QLineF()

        self.setZValue(-1)
        self.adjust()

    def boundingRect(self) -> QRectF:
        """
        Returns a rect with corners at the centers of the source and
        destination node.
        """
        return (
            QRectF(self._line.p1(), self._line.p2())
            .normalized()
            .adjusted(
                -self._thickness - self._arrow_size,
                -self._thickness - self._arrow_size,
                self._thickness + self._arrow_size,
                self._thickness + self._arrow_size,
            )
        )

    def adjust(self):
        """
        Update edge position from source and destination node.
        This method is called from Node::itemChange
        """
        self.prepareGeometryChange()

        self._source_pos = self._source.pos() + self._source.boundingRect().center()
        target_pos = self.get_arrow_target()

        self._line = QLineF(self._source_pos, target_pos)

        angle = math.atan2(self._line.dy(), -self._line.dx())

        arrow_p1 = QPointF(
            math.sin(angle + math.pi / 3) * self._arrow_size,
            math.cos(angle + math.pi / 3) * self._arrow_size,
        )
        arrow_p2 = QPointF(
            math.sin(angle + math.pi * 2 / 3) * self._arrow_size,
            math.cos(angle + math.pi * 2 / 3) * self._arrow_size,
        )

        self._arrow_head_polygon = QPolygonF([QPointF(0, 0), arrow_p1, arrow_p2])
        self._arrow_head_polygon.translate(target_pos)

    def get_arrow_target(self) -> QPointF:
        """
        Calculate the end position of the arrow taking into account the size
        and shape of the destination node and the input id that this node represents
        """
        return self.get_edge_point(self._dest.pos(), self._dest.shape(), self._source_pos, self._dest_index, self._dest_num_inputs)

    def get_edge_point(
        self, shape_offset: QPointF, shape: QPainterPath, out_point: QPointF, offset: int, slots: int
    ) -> QPointF:

        # Translate the shape into the destination point coordinate system
        shape.translate(shape_offset)

        if shape.contains(out_point):
            return out_point

        # Move point along the line until it intersects the shape. We assume
        # there is only 1 intersection and use binary search.
        shape_box = shape.boundingRect()

        left_offset = shape_box.width() * (offset + 1) / (slots + 1)
        in_point = shape_box.topLeft() + QPointF(left_offset, 0)

        close_enough = (
            lambda a, b: abs(a.x() - b.x()) < 0.1 and abs(a.y() - b.y()) < 0.1
        )

        while not close_enough(out_point, in_point):
            mid = (out_point + in_point) / 2

            if shape.contains(mid):
                in_point = mid
            else:
                out_point = mid

        return out_point

    def paint(self, painter: QPainter, option: QStyleOptionGraphicsItem, widget=None):
        """Override from QGraphicsItem

        Draw Edge. This method is called from Edge::adjust
        """
        painter.setRenderHints(QPainter.RenderHint.Antialiasing)
        pen_style = Qt.PenStyle.DashLine if self._is_dotted else Qt.PenStyle.SolidLine
        painter.setPen(QPen(QColor(self._color), self._thickness, pen_style, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
        painter.setBrush(QBrush(self._color))
        painter.drawLine(self._line)
        if not self._is_dotted:
            painter.drawPolygon(self._arrow_head_polygon)


class GraphView(QGraphicsView):
    def __init__(self, graph: typing.Optional[networkx.DiGraph], parent=None):
        """GraphView constructor

        This widget can display a directed graph.
        """
        super().__init__()

        self._main_window = parent
        self._graph = graph
        self._scene = QGraphicsScene()
        self.setScene(self._scene)
        self.setBackgroundBrush(QColor("white"))
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)

        # Used to add space between nodes
        self._graph_scale = 10

        # Map node name to Node object
        self._nodes_map: dict[str, tuple[Node, typing.Any]] = {}

        if self._graph is not None:
            self._load_graph()
            self.set_pos()

    def set_graph(self, graph: typing.Optional[networkx.DiGraph]):
        """Set the networkx graph"""
        self._graph = graph

        if graph is None:
            self.scene().clear()
            self._nodes_map.clear()
        else:
            self._load_graph()
            self.set_pos()

    def set_pos(self):
        """Set the position of nodes"""
        # Compute node position from layout function
        positions = layout_algorithm(self._graph)

        # Change position of all nodes
        for node, pos in positions.items():
            x, y = pos
            item, _ = self._nodes_map[node]
            item_rect = item.boundingRect()
            w, h = item_rect.width(), item_rect.height()

            item.setPos(x - w / 2, y - h / 2)

    def _load_graph(self):
        """Load graph into QGraphicsScene using Node class and Edge class"""

        # TODO: Don't remove elements (nodes / edges) that are already in the
        # scene, to make the specific changes between graphs more clear.
        self.scene().clear()
        self._nodes_map.clear()

        # Add nodes
        for node, node_item in self._graph.nodes(data="node_item"):
            if node_item is None:
                print(f"Warning: node_item is None for node: {node!r}")
                continue
            item = Node(node_item)
            self.scene().addItem(item)
            self._nodes_map[node] = (item, node_item)

        # Add edges
        for a, b, dotted in self._graph.edges.data('dotted', default=False):
            source, source_item = self._nodes_map[a]
            dest, dest_item = self._nodes_map[b]

            # When the edge points into an Operation, the arrow head of the edge
            # should be offset to indicate the input order.
            if isinstance(dest_item, Operation):
                offset = dest_item._in.index(source_item)
                slots = len(dest_item._in)
            else:
                offset = 0
                slots = 1

            self.scene().addItem(Edge(source, dest, offset, slots, dotted))

    def get_nodes(self) -> Iterator[Node]:
        """
        Returns an iterator that yields all nodes that are in the scene.
        """
        return filter(lambda i: isinstance(i, Node), self.scene().items())

    def wheelEvent(self, event):
        """
        Called whenever the mouse wheel is moved while the cursor is over the
        graph view. This zooms the view in or out, depending on the direction of
        the mouse wheel movement.
        """
        if event.angleDelta().y() > 0:
            self._main_window._handle_zoom_in(cursor_is_center=True)
        else:
            self._main_window._handle_zoom_out(cursor_is_center=True)

    def set_zoom(self, zoom_scale: float, *, cursor_is_center: bool = False):
        """
        Set the zoom to a specific level
        """

        transform = QTransform()
        transform.scale(zoom_scale, zoom_scale)

        if cursor_is_center:
            self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)

        self.setTransform(transform)

        if cursor_is_center:
            # (reset back to original transformation anchor)
            self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorViewCenter)


class ZoomSliderWidget(QWidget):

    def __init__(self, num_zoom_levels: int, initial_idx: int, parent: "MainWindow"):
        """
        Creates and initializes the widget
        """
        super().__init__()

        self.parent = parent
        self.num_zoom_levels = num_zoom_levels

        self.slider = QSlider(Qt.Horizontal)
        self.minus_button = QPushButton('-')
        self.plus_button = QPushButton('+')

        self.slider.setMinimum(0)
        self.slider.setMaximum(num_zoom_levels - 1)
        self.slider.setTickInterval(2)
        self.slider.setTickPosition(QSlider.TicksAbove)
        self.slider.setPageStep(1)
        self.slider.setTracking(True)
        self.slider.setSliderPosition(initial_idx)
        self.slider.valueChanged.connect(self._handle_slider_moved)

        self.minus_button.setFlat(True)
        self.plus_button.setFlat(True)
        self.minus_button.clicked.connect(parent._handle_zoom_out)
        self.plus_button.clicked.connect(parent._handle_zoom_in)

        layout = QHBoxLayout(self)
        layout.addWidget(self.minus_button)
        layout.addWidget(self.slider)
        layout.addWidget(self.plus_button)

    def _handle_slider_moved(self):
        """
        Handle the slider being moved - pass the new zoom index to the parent
        """
        self.parent._handle_update_zoom(self.slider.value())

    def set_zoom_level(self, new_zoom_idx: int):
        """
        Sets the slider position to the given index and updates the buttons
        accordingly.
        """
        self.slider.setSliderPosition(new_zoom_idx)
        self.minus_button.setEnabled(new_zoom_idx > 0)
        self.plus_button.setEnabled(new_zoom_idx < self.num_zoom_levels - 1)


class SearchWidget(QWidget):
    _search_results: list[Node] = []
    _current_search_result: typing.Optional[Node] = None
    _search_idx: int = -1
    _graph_view: GraphView

    def __init__(self, graph_view: GraphView, parent: QWidget):
        super().__init__(parent)
        self._graph_view = graph_view

        self._next_button = QPushButton("Next", self)
        self._prev_button = QPushButton("Prev", self)
        self._search_button = QPushButton("?", self)
        self._search_box = QLineEdit(self)
        self._status = QLabel("Status")

        layout = QGridLayout(self)
        layout.addWidget(self._search_box, 0, 0, 1, 2)
        layout.addWidget(self._search_button, 0, 2)
        layout.addWidget(self._prev_button, 1, 0)
        layout.addWidget(self._status, 1, 1)
        layout.addWidget(self._next_button, 1, 2)

        self._next_button.clicked.connect(self._handle_next)
        self._prev_button.clicked.connect(self._handle_prev)
        self._search_button.clicked.connect(self._handle_search)

        self.disable(clear_search_text=True)

    def _handle_next(self, e):
        self._change_focus(self._search_idx + 1)

    def _handle_prev(self, e):
        self._change_focus(self._search_idx - 1)

    def _handle_search(self, e):
        search_str = self._search_box.text()

        self.disable(clear_search_text=False)

        for node in self._graph_view.get_nodes():
            if search_str in node._name:
                self._search_results.append(node)

        self.enable()
        self._change_focus(0)

    def disable(self, clear_search_text: bool):
        """
        Resets and disables all UI elements and the internal state of the widget.
        If 'clear_search_text' is set, also clears the text in the search box.
        """
        if clear_search_text:
            self._search_box.setText("")
        self._search_box.setEnabled(False)
        self._search_button.setEnabled(False)
        self._prev_button.setEnabled(False)
        self._next_button.setEnabled(False)
        self._status.setText("")

        self._search_idx = -1
        self._search_results = []
        self._current_search_result = None

    def enable(self):
        self._search_box.setEnabled(True)
        self._search_button.setEnabled(True)
        self._prev_button.setEnabled(True)
        self._next_button.setEnabled(True)

    def _change_focus(self, new_idx: int):
        """
        Changes the focus of the main graph view to the search result at index
        new_idx and updates the internal state of the search widget.
        """
        num_results = len(self._search_results)
        old_idx = self._search_idx
        self._search_idx = min(num_results - 1, max(0, new_idx))
        if self._search_idx == old_idx:
            return

        self._current_search_result = self._search_results[self._search_idx]
        self._graph_view.centerOn(self._current_search_result)
        self._graph_view.scene().setFocusItem(self._current_search_result)
        self._current_search_result.highlight()

        self._prev_button.setEnabled(self._search_idx != 0)
        self._next_button.setEnabled(self._search_idx != num_results - 1)
        self._status.setText(f"{self._search_idx + 1} / {num_results}")


class InformationDockWidget(QDockWidget):
    """
    The widget that contains the extra information such as the
    P-CODE and diff view as tabs.
    """

    def __init__(self, parent: QWidget):
        super().__init__("Information", parent)

        # Create the tab widget
        self.pcode_tab = QWidget()
        self.diff_tab = QWidget()
        self.pcode_tab = QTextEdit(self)
        self.diff_tab = QTextEdit(self)
        self.diff_tab.setReadOnly(True)
        self.pcode_tab.setReadOnly(True)
        self.diff_tab.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        self.pcode_tab.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)

        tab_widget = QTabWidget(self)
        tab_widget.addTab(self.pcode_tab, "P-CODE")
        tab_widget.addTab(self.diff_tab, "Diff")

        self.setWidget(tab_widget)

    def set_contents(self, pcode_text: str, diff_text: str):
        self.pcode_tab.setText(pcode_text)
        self.diff_tab.setText(diff_text)
