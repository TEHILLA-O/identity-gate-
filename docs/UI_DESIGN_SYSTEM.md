# Interface

The control centre is a dark workspace. There is no permanent left sidebar. A command ribbon holds the environment, organisation, search, Keycloak status, open finding count, density toggle, and the signed-in account. A horizontal rail switches Overview, Identity Graph, Directory, Lifecycle, Provisioning, Access Reviews, Policies, Security, Audit, and Reports.

Ctrl or Cmd+K opens the command palette. It searches identities through `/api/v1/search` and jumps to a workspace. Selecting a person opens the inspector and focuses the graph.

The graph is React Flow. Nodes and edges come from `/api/v1/graph`. Colours distinguish people, groups, roles, permissions, applications, and findings. Privileged edges are amber. Finding edges are coral. The layout is columnar so a grant reads left to right: person, department or manager, group, role, permission, application. A table of the same access paths is available from the identity inspector.

Typography is IBM Plex Sans for the interface and IBM Plex Mono for identifiers, timestamps, and correlation ids. Motion is limited to the graph edge animation on findings. A panel updates only after the API returns.

Density mode tightens the tables. Focus states remain on buttons and inputs. The sample applications are intentionally plain. The control centre is the product surface.
