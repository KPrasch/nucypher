<%!
def hex_to_rgb(color_hex):
    # Expects a color in the form "#abcdef"
    r = int(color_hex[1:3], 16)
    g = int(color_hex[3:5], 16)
    b = int(color_hex[5:7], 16)
    return r, g, b

def contrast_color(color_hex):
    r, g, b = hex_to_rgb(color_hex)
    # As defined in https://www.w3.org/WAI/ER/WD-AERT/#color-contrast
    # Ranges from 0 to 255
    intensity = (r * 299 + g * 587 + b * 114) / 1000
    if intensity > 128:
        return "black"
    else:
        return "white"

def character_span(character):
    color = character.color_hex
    symbol = character.symbol
    return f'<span class="symbol" style="color: {contrast_color(color)}; background-color: {color}">{symbol}</span>'
%>

<%def name="fleet_state_icon(state)">
%if not state:
<span class="fleet-state-empty">&mdash;</span>
%else:
<div class="fleet-state-container" title="${state.nickname}">
    <div class="state-icon-wrapper">
        <span class="state-icon">${"".join(character_span(character) for character in state.nickname.characters)}</span>
    </div>
    <div class="state-info">
        <div class="state-population">${state.population} nodes</div>
        <div class="state-checksum">0x${bytes(state.checksum)[0:8].hex()}</div>
    </div>
</div>
%endif
</%def>


<%def name="node_info(node)">
<div class="node-container">
    <div class="node-icon-wrapper">
        <span class="node-icon">${"".join(character_span(character) for character in node.nickname.characters)}</span>
    </div>
    <div class="node-details">
        <a href="https://${node.rest_url}/status" class="node-nickname">
            ${node.nickname}
        </a>
        <div class="node-address">${node.staker_address}</div>
    </div>
</div>
</%def>


<%def name="main(status_info)">
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ursula Node Status • TACo Network</title>
    <link rel="icon" type="image/x-icon" href="https://taco.build/favicon.ico"/>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
</head>

<style type="text/css">
    :root {
        --bg-primary: #0a0a0f;
        --bg-secondary: #12121a;
        --bg-card: #1a1a24;
        --bg-card-hover: #21212e;
        --border-primary: #2a2a38;
        --border-accent: #3a3a4a;
        --text-primary: #ffffff;
        --text-secondary: #b4b6c7;
        --text-muted: #6c7293;
        --accent-green: #00d084;
        --accent-orange: #f0932b;
        --accent-blue: #4f96ff;
        --error-red: #ff6b6b;
        --shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
        --shadow-lg: 0 10px 40px rgba(0, 0, 0, 0.2);
        --border-radius: 12px;
        --border-radius-lg: 16px;
    }

    * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
    }

    body {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        background: var(--bg-primary);
        color: var(--text-primary);
        line-height: 1.6;
        min-height: 100vh;
        padding: 1rem;
        background-image: 
            radial-gradient(circle at 25% 25%, rgba(0, 208, 132, 0.02) 0%, transparent 50%),
            radial-gradient(circle at 75% 75%, rgba(240, 147, 43, 0.02) 0%, transparent 50%);
    }

    .container {
        max-width: 1200px;
        margin: 0 auto;
    }

    .header {
        text-align: center;
        margin-bottom: 2rem;
        padding: 2rem 0;
    }

    .header h1 {
        font-size: 2.5rem;
        font-weight: 700;
        margin-bottom: 0.5rem;
        background: linear-gradient(135deg, var(--accent-green), var(--accent-orange));
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
    }

    .header .subtitle {
        color: var(--text-secondary);
        font-size: 1.1rem;
    }

    .card {
        background: var(--bg-card);
        border: 1px solid var(--border-primary);
        border-radius: var(--border-radius-lg);
        padding: 2rem;
        margin-bottom: 2rem;
        box-shadow: var(--shadow);
        transition: all 0.2s ease;
    }

    .card:hover {
        background: var(--bg-card-hover);
        border-color: var(--border-accent);
        box-shadow: var(--shadow-lg);
    }

    .card-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin-bottom: 1.5rem;
        padding-bottom: 1rem;
        border-bottom: 1px solid var(--border-primary);
    }

    .card-title {
        font-size: 1.5rem;
        font-weight: 600;
        color: var(--text-primary);
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }

    .status-badge {
        background: var(--accent-green);
        color: white;
        padding: 0.25rem 0.75rem;
        border-radius: 20px;
        font-size: 0.875rem;
        font-weight: 500;
        display: flex;
        align-items: center;
        gap: 0.25rem;
    }

    .status-badge::before {
        content: '●';
        animation: pulse 2s infinite;
    }

    @keyframes pulse {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.5; }
    }

    .node-info-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
        gap: 1.5rem;
        margin-bottom: 2rem;
    }

    .info-item {
        display: flex;
        flex-direction: column;
        gap: 0.5rem;
    }

    .info-label {
        font-size: 0.875rem;
        font-weight: 500;
        color: var(--text-muted);
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }

    .info-value {
        font-size: 1rem;
        font-weight: 500;
        color: var(--text-primary);
    }

    .info-value.mono {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.9rem;
        background: var(--bg-secondary);
        padding: 0.5rem 0.75rem;
        border-radius: var(--border-radius);
        border: 1px solid var(--border-primary);
        word-break: break-all;
    }

    .node-container {
        display: flex;
        align-items: center;
        gap: 1rem;
        padding: 1rem;
        background: var(--bg-secondary);
        border: 1px solid var(--border-primary);
        border-radius: var(--border-radius);
        transition: all 0.2s ease;
    }

    .node-container:hover {
        background: var(--bg-card);
        border-color: var(--accent-green);
        transform: translateY(-2px);
        box-shadow: var(--shadow);
    }

    .node-icon-wrapper {
        display: flex;
        align-items: center;
        justify-content: center;
        min-width: 60px;
    }

    .node-icon {
        font-size: 2.5rem;
        font-family: 'JetBrains Mono', monospace;
        display: flex;
        gap: 2px;
        filter: drop-shadow(0 2px 4px rgba(0, 0, 0, 0.3));
    }

    .node-details {
        flex: 1;
        min-width: 0;
    }

    .node-nickname {
        color: var(--text-primary);
        font-weight: 600;
        font-size: 1.1rem;
        text-decoration: none;
        transition: color 0.2s ease;
    }

    .node-nickname:hover {
        color: var(--accent-green);
    }

    .node-address {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.8rem;
        color: var(--text-muted);
        margin-top: 0.25rem;
    }

    .fleet-state-container {
        display: flex;
        align-items: center;
        gap: 0.75rem;
        padding: 0.75rem 1rem;
        background: var(--bg-secondary);
        border: 1px solid var(--border-primary);
        border-radius: var(--border-radius);
        transition: all 0.2s ease;
        margin-right: 1rem;
        margin-bottom: 0.5rem;
        display: inline-flex;
    }

    .fleet-state-container:hover {
        border-color: var(--accent-green);
        transform: scale(1.02);
    }

    .state-icon-wrapper {
        display: flex;
        align-items: center;
    }

    .state-icon {
        font-size: 2rem;
        font-family: 'JetBrains Mono', monospace;
        display: flex;
        gap: 2px;
        filter: drop-shadow(0 2px 4px rgba(0, 0, 0, 0.3));
    }

    .state-info {
        display: flex;
        flex-direction: column;
        gap: 0.1rem;
    }

    .state-population {
        font-size: 0.875rem;
        font-weight: 500;
        color: var(--text-primary);
    }

    .state-checksum {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.75rem;
        color: var(--text-muted);
    }

    .fleet-state-empty {
        color: var(--text-muted);
        font-size: 1.5rem;
        padding: 0.75rem 1rem;
    }

    .symbol {
        padding: 0.1em 0.15em;
        border-radius: 4px;
        font-weight: 600;
        margin: 0 1px;
    }

    .fleet-states-wrapper {
        display: flex;
        flex-wrap: wrap;
        gap: 0.5rem;
        align-items: center;
    }

    .known-nodes-section {
        margin-top: 3rem;
    }

    .known-nodes-header {
        font-size: 1.25rem;
        font-weight: 600;
        color: var(--text-primary);
        margin-bottom: 1.5rem;
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }

    .node-count {
        background: var(--accent-green);
        color: white;
        padding: 0.25rem 0.75rem;
        border-radius: 20px;
        font-size: 0.875rem;
        font-weight: 500;
    }

    .nodes-grid {
        display: grid;
        gap: 1rem;
        margin-bottom: 2rem;
    }

    .node-table {
        background: var(--bg-secondary);
        border: 1px solid var(--border-primary);
        border-radius: var(--border-radius);
        overflow: hidden;
    }

    .node-table-header {
        display: grid;
        grid-template-columns: 2fr 1fr 1fr 1.5fr;
        gap: 1rem;
        padding: 1rem;
        background: var(--bg-card);
        border-bottom: 1px solid var(--border-primary);
        font-weight: 600;
        color: var(--text-secondary);
        font-size: 0.875rem;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }

    .node-table-row {
        display: grid;
        grid-template-columns: 2fr 1fr 1fr 1.5fr;
        gap: 1rem;
        padding: 1rem;
        border-bottom: 1px solid var(--border-primary);
        transition: background-color 0.2s ease;
        align-items: center;
    }

    .node-table-row:last-child {
        border-bottom: none;
    }

    .node-table-row:hover {
        background: var(--bg-card);
    }

    .timestamp {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.8rem;
        color: var(--text-muted);
    }

    .rpc-proxy-section {
        margin-top: 2rem;
    }

    .proxy-stats {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
        gap: 1rem;
        margin-top: 1rem;
    }

    .stat-item {
        background: var(--bg-secondary);
        padding: 1rem;
        border-radius: var(--border-radius);
        border: 1px solid var(--border-primary);
        text-align: center;
        transition: all 0.2s ease;
    }

    .stat-item:hover {
        border-color: var(--accent-green);
        transform: translateY(-2px);
    }

    .stat-value {
        font-size: 1.5rem;
        font-weight: 700;
        color: var(--accent-green);
        font-family: 'JetBrains Mono', monospace;
    }

    .stat-label {
        font-size: 0.8rem;
        color: var(--text-muted);
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-top: 0.25rem;
    }

    .footer {
        text-align: center;
        padding: 3rem 0 2rem;
        margin-top: 4rem;
        border-top: 1px solid var(--border-primary);
    }

    .footer-content {
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 0.5rem;
        color: var(--text-muted);
        font-size: 0.9rem;
    }

    .taco-emoji {
        font-size: 1.2rem;
        animation: taco-bounce 2s ease-in-out infinite;
    }

    @keyframes taco-bounce {
        0%, 100% { transform: translateY(0); }
        50% { transform: translateY(-4px); }
    }

    .footer-links {
        margin-top: 1rem;
        display: flex;
        justify-content: center;
        gap: 2rem;
    }

    .footer-links a {
        color: var(--text-muted);
        text-decoration: none;
        font-size: 0.8rem;
        transition: color 0.2s ease;
    }

    .footer-links a:hover {
        color: var(--accent-green);
    }

    /* Mobile Responsiveness */
    @media (max-width: 768px) {
        body {
            padding: 0.5rem;
        }

        .header h1 {
            font-size: 2rem;
        }

        .card {
            padding: 1.5rem;
        }

        .node-info-grid {
            grid-template-columns: 1fr;
            gap: 1rem;
        }

        .node-table-header,
        .node-table-row {
            grid-template-columns: 1fr;
            gap: 0.5rem;
        }

        .node-table-header {
            display: none;
        }

        .node-table-row {
            padding: 1rem;
            display: block;
        }

        .proxy-stats {
            grid-template-columns: repeat(2, 1fr);
        }

        .footer-links {
            flex-direction: column;
            gap: 1rem;
        }

        .fleet-states-wrapper {
            flex-direction: column;
            align-items: flex-start;
        }
    }
</style>

<body>
    <div class="container">
        <div class="header">
            <h1>Ursula Node Status</h1>
            <div class="subtitle">TACo Network Node Dashboard</div>
        </div>

        <!-- Main Node Information Card -->
        <div class="card">
            <div class="card-header">
                <h2 class="card-title">
                    <span class="taco-emoji">🌮</span>
                    This Node
                </h2>
                <div class="status-badge">Online</div>
            </div>
            
            <div class="node-container" style="margin-bottom: 2rem; background: var(--bg-primary); border-color: var(--accent-green);">
                ${node_info(status_info)}
            </div>

            <div class="node-info-grid">
                <div class="info-item">
                    <div class="info-label">Version</div>
                    <div class="info-value">v${status_info.version}</div>
                </div>
                
                <div class="info-item">
                    <div class="info-label">Domain</div>
                    <div class="info-value">${status_info.domain}</div>
                </div>
                
                <div class="info-item">
                    <div class="info-label">Staker Address</div>
                    <div class="info-value mono">${status_info.staker_address}</div>
                </div>
                
                <div class="info-item">
                    <div class="info-label">Operator Address</div>
                    <div class="info-value mono">${status_info.operator_address}</div>
                </div>
                
                <div class="info-item">
                    <div class="info-label">REST URL</div>
                    <div class="info-value mono">${status_info.rest_url}</div>
                </div>
                
                <div class="info-item">
                    <div class="info-label">Latest Scanned Block</div>
                    <div class="info-value">${status_info.block_height}</div>
                </div>
                
                %if hasattr(status_info, 'balance_eth'):
                <div class="info-item">
                    <div class="info-label">ETH Balance</div>
                    <div class="info-value">${status_info.balance_eth:.4f} ETH</div>
                </div>
                %endif
                
                %if hasattr(status_info, 'ferveo_public_key') and status_info.ferveo_public_key:
                <div class="info-item">
                    <div class="info-label">Ferveo Public Key</div>
                    <div class="info-value mono">${status_info.ferveo_public_key}</div>
                </div>
                %endif
            </div>

            <div class="info-item">
                <div class="info-label">Current Fleet State</div>
                <div class="fleet-states-wrapper">
                    ${fleet_state_icon(status_info.fleet_state)}
                </div>
            </div>

            %if status_info.previous_fleet_states:
            <div class="info-item" style="margin-top: 1.5rem;">
                <div class="info-label">Previous Fleet States</div>
                <div class="fleet-states-wrapper">
                    %for state in status_info.previous_fleet_states:
                        ${fleet_state_icon(state)}
                    %endfor
                </div>
            </div>
            %endif
        </div>

        <!-- eRPC Proxy Status Card -->
        %if hasattr(status_info, 'rpc_proxy') and status_info.rpc_proxy is not None:
        <div class="card rpc-proxy-section">
            <div class="card-header">
                <h2 class="card-title">
                    ⚡ eRPC Proxy Status
                </h2>
                <div class="status-badge">${'Enabled' if status_info.rpc_proxy.get('enabled', False) else 'Disabled'}</div>
            </div>
            
            <div class="proxy-stats">
                %if 'port' in status_info.rpc_proxy:
                <div class="stat-item">
                    <div class="stat-value">${status_info.rpc_proxy['port']}</div>
                    <div class="stat-label">Port</div>
                </div>
                %endif
                
                %if 'pid' in status_info.rpc_proxy:
                <div class="stat-item">
                    <div class="stat-value">${status_info.rpc_proxy['pid']}</div>
                    <div class="stat-label">Process ID</div>
                </div>
                %endif
                
                %if 'uptime' in status_info.rpc_proxy:
                <div class="stat-item">
                    <div class="stat-value">${status_info.rpc_proxy['uptime']}</div>
                    <div class="stat-label">Uptime</div>
                </div>
                %endif
                
                %if 'requests' in status_info.rpc_proxy:
                <div class="stat-item">
                    <div class="stat-value">${status_info.rpc_proxy['requests']}</div>
                    <div class="stat-label">Requests</div>
                </div>
                %endif
                
                %if 'errors' in status_info.rpc_proxy:
                <div class="stat-item">
                    <div class="stat-value" style="color: ${('var(--error-red)' if status_info.rpc_proxy['errors'] > 0 else 'var(--accent-green)')}">${status_info.rpc_proxy['errors']}</div>
                    <div class="stat-label">Errors</div>
                </div>
                %endif
            </div>
        </div>
        %endif

        <!-- Known Nodes Section -->
        %if status_info.known_nodes is not None:
        <%
            verified_nodes = [node_status for node_status in status_info.known_nodes if node_status.verified]
            unverified_nodes = [node_status for node_status in status_info.known_nodes if not node_status.verified]
        %>
        
        %for node_set, qualifier, icon in [(verified_nodes, "verified", "✓"), (unverified_nodes, "unverified", "⚠")]:
        %if node_set:
        <div class="card known-nodes-section">
            <h3 class="known-nodes-header">
                ${icon} ${len(node_set)} ${qualifier} ${"node" if len(node_set) == 1 else "nodes"}
                <span class="node-count">${len(node_set)}</span>
            </h3>

            <div class="node-table">
                <div class="node-table-header">
                    <div>Node</div>
                    <div>Launched</div>
                    <div>Last Contact</div>
                    <div>Fleet State</div>
                </div>
                
                %for node in node_set:
                <div class="node-table-row">
                    <div>
                        ${node_info(node)}
                    </div>
                    <div>
                        <span class="timestamp">${node.timestamp.iso8601()}</span>
                    </div>
                    <div>
                        %if node.last_learned_from is not None:
                        <span class="timestamp">${node.last_learned_from.iso8601()}</span>
                        %else:
                        <span class="fleet-state-empty">—</span>
                        %endif
                    </div>
                    <div>
                        ${fleet_state_icon(node.recorded_fleet_state)}
                    </div>
                </div>
                %endfor
            </div>
        </div>
        %endif
        %endfor
        %endif

        <!-- Footer -->
        <div class="footer">
            <div class="footer-content">
                <span>Powered by</span>
                <span class="taco-emoji">🌮</span>
                <span><strong>TACo Network</strong></span>
            </div>
            <div class="footer-links">
                <a href="https://taco.build" target="_blank">TACo Official</a>
                <a href="https://docs.threshold.network/app-development/taco" target="_blank">Documentation</a>
                <a href="https://github.com/nucypher/nucypher" target="_blank">GitHub</a>
            </div>
        </div>
    </div>
</body>
</html>
</%def>