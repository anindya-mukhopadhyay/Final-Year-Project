const API_BASE_URL = "http://127.0.0.1:5001";


async function getJSON(
    endpoint,
    options = {}
) {
    const response = await fetch(
        `${API_BASE_URL}${endpoint}`,
        options
    );

    if (!response.ok) {
        throw new Error(
            `API request failed: ${response.status}`
        );
    }

    return response.json();
}


/* =========================================================
   LOAD DASHBOARD
========================================================= */

async function loadDashboard() {

    try {

        const [
            networkData,
            chainData
        ] = await Promise.all([
            getJSON("/network"),
            getJSON("/chain")
        ]);


        updateStatistics(
            networkData,
            chainData
        );


        renderNodes(
            networkData
        );


        renderBlocks(
            chainData.chain || []
        );


    } catch (error) {

        console.error(
            "Dashboard loading failed:",
            error
        );

        showError(
            error.message
        );
    }
}


/* =========================================================
   UPDATE STATISTICS
========================================================= */

function updateStatistics(
    networkData,
    chainData
) {

    const blockCount =
        Array.isArray(
            chainData.chain
        )
            ? chainData.chain.length
            : (Number(networkData.blocks) || 0);


    // Actual network peers currently reachable
    const peerCount =
        networkData.connected_peers_count !== undefined
            ? networkData.connected_peers_count
            : (Array.isArray(networkData.peers) ? networkData.peers.length : 0);


    const pendingCount =
        Number(
            networkData.pending_transactions
        ) || 0;


    document.getElementById(
        "blockCount"
    ).textContent =
        blockCount;


    document.getElementById(
        "peerCount"
    ).textContent =
        peerCount;


    document.getElementById(
        "pendingCount"
    ).textContent =
        pendingCount;


    const currentNodeId =
        networkData.current_node ||
        networkData.node_id ||
        "node-1";


    document.getElementById(
        "currentNode"
    ).textContent =
        currentNodeId;


    document.getElementById(
        "healthNode"
    ).textContent =
        currentNodeId;


    document.getElementById(
        "healthBlocks"
    ).textContent =
        blockCount;


    document.getElementById(
        "healthPeers"
    ).textContent =
        peerCount;


    document.getElementById(
        "tableBlockCount"
    ).textContent =
        blockCount;


    const valid =
        networkData.chain_valid === true;


    document.getElementById(
        "chainStatus"
    ).textContent =
        valid
            ? "Chain valid"
            : "Chain validation failed";


    document.getElementById(
        "networkStatus"
    ).textContent =
        networkData.network_status ||
        (valid ? "Online" : "Warning");
}


/* =========================================================
   RENDER NODES
========================================================= */

function renderNodes(
    networkData
) {

    const container =
        document.getElementById(
            "nodesContainer"
        );


    const nodeList =
        Array.isArray(networkData.nodes) && networkData.nodes.length > 0
            ? networkData.nodes
            : [
                {
                    id: networkData.current_node || networkData.node_id || "node-1",
                    role: networkData.role || "UNIVERSITY",
                    port: networkData.port || 5001,
                    blocks: networkData.blocks || 0,
                    status: networkData.chain_valid ? "ONLINE" : "ERROR",
                    is_current: true
                }
            ];


    if (
        nodeList.length === 0
    ) {

        container.innerHTML =
            `
            <div class="empty-state">
                No network nodes found.
            </div>
            `;

        return;
    }


    container.innerHTML =
        nodeList.map(
            node => {

                const isOnline =
                    String(node.status).toUpperCase() === "ONLINE";

                const dotClass =
                    isOnline
                        ? "status-dot"
                        : "status-dot offline";

                const roleLabel =
                    node.is_current
                        ? `${node.role} (CURRENT)`
                        : node.role;

                return `
                    <div class="node-card">

                        <div class="node-top">

                            <span class="node-role">
                                ${escapeHTML(roleLabel)}
                            </span>

                            <span class="${dotClass}"></span>

                        </div>

                        <div class="node-name">
                            ${escapeHTML(node.id)}
                        </div>

                        <div class="node-port">
                            Port ${escapeHTML(
                                String(node.port)
                            )}
                        </div>

                        <div class="node-meta">

                            <div>
                                <span>Blocks</span>
                                <strong>
                                    ${escapeHTML(
                                        String(node.blocks)
                                    )}
                                </strong>
                            </div>

                            <div>
                                <span>Status</span>
                                <strong class="${isOnline ? 'online-status' : 'offline-status'}">
                                    ${escapeHTML(
                                        String(node.status)
                                    )}
                                </strong>
                            </div>

                        </div>

                    </div>
                `;
            }
        ).join("");
}


/* =========================================================
   RENDER BLOCKS
========================================================= */

function renderBlocks(
    chain
) {

    const tbody =
        document.getElementById(
            "blocksTable"
        );


    if (
        !Array.isArray(chain)
        ||
        chain.length === 0
    ) {

        tbody.innerHTML =
            `
            <tr>
                <td
                    colspan="6"
                    class="empty-cell"
                >
                    No blockchain blocks available.
                </td>
            </tr>
            `;

        return;
    }


    const recentBlocks =
        [...chain]
            .reverse()
            .slice(0, 10);


    tbody.innerHTML =
        recentBlocks
            .map(
                block => {

                    const transactions =
                        Array.isArray(
                            block.data
                        )
                            ? block.data
                            : [];


                    let type =
                        block.index === 0
                            ? "GENESIS"
                            : "BLOCK";


                    let transactionId =
                        "—";


                    if (
                        transactions.length
                    ) {

                        const firstTransaction =
                            transactions[0];

                        type =
                            firstTransaction
                                ?.data
                                ?.type ||
                            "TRANSACTION";

                        transactionId =
                            firstTransaction
                                ?.transaction_id ||
                            "—";
                    }


                    return `
                        <tr>

                            <td class="block-number">
                                #${escapeHTML(
                                    String(
                                        block.index
                                    )
                                )}
                            </td>

                            <td>

                                <span class="type-badge">
                                    ${escapeHTML(
                                        type
                                    )}
                                </span>

                            </td>

                            <td>

                                <span class="hash-text">
                                    ${escapeHTML(
                                        transactionId
                                    )}
                                </span>

                            </td>

                            <td>

                                <span class="hash-text">
                                    ${escapeHTML(
                                        block.previous_hash
                                    )}
                                </span>

                            </td>

                            <td>

                                <span class="hash-text">
                                    ${escapeHTML(
                                        block.hash
                                    )}
                                </span>

                            </td>

                            <td>

                                <span class="confirmed">
                                    ● CONFIRMED
                                </span>

                            </td>

                        </tr>
                    `;
                }
            )
            .join("");
}


/* =========================================================
   ERROR
========================================================= */

function showError(
    message
) {

    document.getElementById(
        "networkStatus"
    ).textContent =
        "Offline";


    document.getElementById(
        "chainStatus"
    ).textContent =
        message;


    document.getElementById(
        "nodesContainer"
    ).innerHTML =
        `
        <div class="empty-state">
            Unable to connect to AnswerChain backend.
            <br>
            Start the blockchain node on port 5001.
        </div>
        `;
}


/* =========================================================
   SAFE HTML
========================================================= */

function escapeHTML(
    value
) {

    return String(value)
        .replaceAll(
            "&",
            "&amp;"
        )
        .replaceAll(
            "<",
            "&lt;"
        )
        .replaceAll(
            ">",
            "&gt;"
        )
        .replaceAll(
            '"',
            "&quot;"
        )
        .replaceAll(
            "'",
            "&#039;"
        );
}


/* =========================================================
   INITIAL LOAD
========================================================= */

document.addEventListener(
    "DOMContentLoaded",
    () => {

        loadDashboard();

        setInterval(
            loadDashboard,
            10000
        );

    }
);