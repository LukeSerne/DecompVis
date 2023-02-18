from PySide6.QtCore import QLineF, QPointF, QRectF, Qt
from PySide6.QtGui import (
    QBrush,
    QColor,
    QPainter,
    QPen,
    QPolygonF,
    QFontMetricsF,
    QFont,
    QPainterPath,
)
from PySide6.QtWidgets import (
    QGraphicsItem,
    QGraphicsObject,
    QGraphicsScene,
    QGraphicsView,
    QStyleOptionGraphicsItem,
    QWidget,
)

import networkx
import math
import typing

from util import Operation


class Node(QGraphicsObject):

    """A QGraphicsItem representing node in a graph"""

    COLORS: dict[str, str] = {
        "green": "#5AD469",
        "red": "#E31E1B",
        "blue": "#1B32E3",
        "yellow": "#D2E31B",
    }

    def __init__(self, item, parent=None):
        """Node constructor

        Args:
            item: Item the node represents
        """
        super().__init__(parent)
        self._name = str(item)
        self._is_op = isinstance(item, Operation)
        self._edges = []
        self._color = self.COLORS["green"] if not self._is_op else self.COLORS["blue"]
        self._is_selected = False

        name_rect = QFontMetricsF(QFont()).boundingRect(self._name)

        self._rect = QRectF(0, 0, name_rect.width() + 10, name_rect.height() + 10)

        self.setFlags(
            QGraphicsItem.ItemIsMovable | QGraphicsItem.ItemSendsGeometryChanges
        )
        self.setCacheMode(QGraphicsItem.DeviceCoordinateCache)

    def add_edge(self, edge):
        """Add an edge to this node

        Args:
            edge (Edge)
        """
        self._edges.append(edge)

    def mousePressEvent(self, ev):
        super().mousePressEvent(ev)

        # Change the colour when the node is right-clicked, highlight the edge
        # when left-clicked.
        if ev.button() == Qt.RightButton:
            color_names = ["green", "red", "blue", "yellow"]
            colors = [self.COLORS[name] for name in color_names]
            color_idx = colors.index(self._color)
            self._color = self.COLORS[color_names[(color_idx + 1) % len(color_names)]]

        elif ev.button() == Qt.LeftButton:
            self._is_selected = not self._is_selected

        else:
            return

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
        base_border = QColor(self._color)
        border_color = base_border.lighter() if self._is_selected else base_border.darker()

        painter.setRenderHints(QPainter.Antialiasing)
        painter.setPen(
            QPen(
                border_color,
                2,
                Qt.SolidLine,
                Qt.RoundCap,
                Qt.RoundJoin,
            )
        )
        painter.setBrush(QBrush(QColor(self._color)))
        painter.drawRoundedRect(self.boundingRect(), 5, 5)
        painter.setPen(QPen(QColor("black")))
        painter.drawText(self.boundingRect(), Qt.AlignCenter, self._name)

    def itemChange(self, change: QGraphicsItem.GraphicsItemChange, value):
        """Override from QGraphicsItem

        Args:
            change (QGraphicsItem.GraphicsItemChange)
            value (Any)

        Returns:
            Any
        """
        if change == QGraphicsItem.ItemPositionHasChanged:
            for edge in self._edges:
                edge.adjust()

        return super().itemChange(change, value)


class Edge(QGraphicsItem):
    def __init__(self, source: Node, dest: Node, parent: QGraphicsItem = None):
        """Edge constructor

        Args:
            source (Node): source node
            dest (Node): destination node
        """
        super().__init__(parent)
        self._source = source
        self._dest = dest

        self._tickness = 2
        self._color = "#2BB53C"
        self._arrow_size = 15

        self._source.add_edge(self)
        self._dest.add_edge(self)

        self._line = QLineF()
        self._target_pos = None

        self.setZValue(-1)
        self.adjust()

    def boundingRect(self) -> QRectF:
        """Override from QGraphicsItem

        Returns:
            QRect: Return node bounding rect
        """
        return (
            QRectF(self._line.p1(), self._line.p2())
            .normalized()
            .adjusted(
                -self._tickness - self._arrow_size,
                -self._tickness - self._arrow_size,
                self._tickness + self._arrow_size,
                self._tickness + self._arrow_size,
            )
        )

    def adjust(self):
        """
        Update edge position from source and destination node.
        This method is called from Node::itemChange
        """
        self.prepareGeometryChange()
        self._line = QLineF(
            self._source.pos() + self._source.boundingRect().center(),
            self._dest.pos() + self._dest.boundingRect().center(),
        )

        self._target_pos = self._arrow_target()

    def _draw_arrow(self, painter: QPainter, start: QPointF, end: QPointF):
        """Draw arrow from start point to end point.

        Args:
            painter (QPainter)
            start (QPointF): start position
            end (QPointF): end position
        """
        painter.setBrush(QBrush(self._color))

        line = QLineF(end, start)

        angle = math.atan2(-line.dy(), line.dx())
        arrow_p1 = line.p1() + QPointF(
            math.sin(angle + math.pi / 3) * self._arrow_size,
            math.cos(angle + math.pi / 3) * self._arrow_size,
        )
        arrow_p2 = line.p1() + QPointF(
            math.sin(angle + math.pi - math.pi / 3) * self._arrow_size,
            math.cos(angle + math.pi - math.pi / 3) * self._arrow_size,
        )

        arrow_head = QPolygonF()
        arrow_head.clear()
        arrow_head.append(line.p1())
        arrow_head.append(arrow_p1)
        arrow_head.append(arrow_p2)
        painter.drawLine(line)
        painter.drawPolygon(arrow_head)

    def _arrow_target(self) -> QPointF:
        """
        Calculate the end position of the arrow taking into account the size
        and shape of the destination node

        Returns:
            QPointF
        """
        return self.get_edge_point(self._dest.pos(), self._dest.shape(), self._line)

    def get_edge_point(
        self, shape_offset: QPointF, shape: QPainterPath, line: QLineF
    ) -> QPointF:

        # Translate the shape into the line coordinate system
        shape.translate(shape_offset)

        # Move point along the line until it intersects the shape. We assume
        # there is only 1 intersection and use binary search.

        # TODO: Possible optimisation: Limit the line to the shape's bounding box
        shape_box = shape.boundingRect()
        shape_box_top = shape_box.top()
        shape_box_bottom = shape_box.bottom()
        shape_box_left = shape_box.left()
        shape_box_right = shape_box.right()

        clamp = lambda v, mi, ma: min(ma, max(mi, v))

        out_point = QPointF(
            clamp(line.p1().x(), shape_box_left, shape_box_right),
            clamp(line.p1().y(), shape_box_top, shape_box_bottom),
        )

        if shape.contains(out_point):
            return out_point

        in_point = QPointF(
            clamp(line.p2().x(), shape_box_left, shape_box_right),
            clamp(line.p2().y(), shape_box_top, shape_box_bottom),
        )

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

        Draw Edge. This method is called from Edge.adjust()

        Args:
            painter (QPainter)
            option (QStyleOptionGraphicsItem)
        """

        if self._source and self._dest:
            painter.setRenderHints(QPainter.Antialiasing)

            painter.setPen(
                QPen(
                    QColor(self._color),
                    self._tickness,
                    Qt.SolidLine,
                    Qt.RoundCap,
                    Qt.RoundJoin,
                )
            )
            self._draw_arrow(painter, self._line.p1(), self._target_pos)


class GraphView(QGraphicsView):
    def __init__(self, graph: networkx.DiGraph, parent=None):
        """GraphView constructor

        This widget can display a directed graph

        Args:
            graph (networkx.DiGraph): a networkx directed graph
        """
        super().__init__()

        self._graph = graph
        self._scene = QGraphicsScene()
        self.setScene(self._scene)
        self.setBackgroundBrush(QColor("white"))

        # Used to add space between nodes
        self._graph_scale = 10

        # Map node name to Node object
        self._nodes_map: dict[str, Node] = {}

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
        """Set start position of nodes"""
        # Compute node position from layout function
        # TODO: Use a different layout function that is better suited to the
        # type of graphs that the decompiler produces.
        positions = networkx.circular_layout(self._graph)
        num_items = len(positions)

        # Change position of all nodes
        for node, pos in positions.items():
            x, y = pos
            x *= self._graph_scale * num_items
            y *= self._graph_scale * num_items
            item = self._nodes_map[node]
            item.setPos(x, y)

    def _load_graph(self):
        """Load graph into QGraphicsScene using Node class and Edge class"""

        # TODO: Don't remove elements (nodes / edges) that are already in the
        # scene, to make the specific changes between graphs more clear.
        self.scene().clear()
        self._nodes_map.clear()

        # Add nodes
        for node, node_item in self._graph.nodes(data="node_item"):
            item = Node(node_item)
            self.scene().addItem(item)
            self._nodes_map[node] = item

        # Add edges
        for a, b in self._graph.edges:
            source = self._nodes_map[a]
            dest = self._nodes_map[b]
            self.scene().addItem(Edge(source, dest))
