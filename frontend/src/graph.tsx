import { Background, Controls, ReactFlow, type Edge, type Node } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { useMemo } from "react";

type GraphNode = { id: string; kind: string; label: string; subtitle?: string; privileged?: boolean; status?: string };
type GraphEdge = { id: string; source: string; target: string; kind: string; privileged?: boolean };

const COLUMN: Record<string, number> = {
  organisation: 0,
  person: 0,
  manager: 1,
  department: 1,
  group: 2,
  role: 3,
  permission: 4,
  application: 5,
  finding: 6,
};

function GateNode({ data }: { data: GraphNode }) {
  return (
    <div className={`node ${data.kind}`}>
      {data.label}
      {data.subtitle ? <small>{data.subtitle}</small> : null}
      {data.privileged ? <small>privileged</small> : null}
    </div>
  );
}

const nodeTypes = { gate: GateNode };

export function IdentityGraph({ graph }: { graph: { nodes: GraphNode[]; edges: GraphEdge[] } }) {
  const { nodes, edges } = useMemo(() => layout(graph), [graph]);
  return (
    <div className="graph-frame">
      <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} fitView minZoom={0.3} proOptions={{ hideAttribution: true }}>
        <Background color="#243041" gap={24} />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}

function layout(graph: { nodes: GraphNode[]; edges: GraphEdge[] }): { nodes: Node[]; edges: Edge[] } {
  const columns = new Map<number, GraphNode[]>();
  for (const node of graph.nodes) {
    const column = COLUMN[node.kind] ?? 2;
    columns.set(column, [...(columns.get(column) ?? []), node]);
  }
  const nodes: Node[] = [];
  for (const [column, items] of columns) {
    items.forEach((item, index) => {
      nodes.push({
        id: item.id,
        type: "gate",
        position: { x: column * 230, y: index * 92 },
        data: item,
      });
    });
  }
  const edges: Edge[] = graph.edges.map((edge) => ({
    id: edge.id,
    source: edge.source,
    target: edge.target,
    label: edge.kind,
    animated: edge.kind === "affects",
    style: { stroke: edge.privileged ? "#e2a23a" : edge.kind === "affects" ? "#e36a62" : "#6d7ea0" },
  }));
  return { nodes, edges };
}
