# THREATSCAPE
### AI-Powered Cyber Threat Analysis and Attack Path Detection

## Overview
THREATSCAPE is an intelligent cybersecurity analysis platform that combines graph-based network analysis and AI to identify compromised assets, analyse potential attack paths, highlight critical infrastructure, and generate actionable threat assessments.

## Key Features
- **Graph-Based Network Visualisation:** Visualises users, devices, servers, and databases and their connections.
- **Compromised Asset Identification:** Highlights assets marked as compromised.
- **Attack Path Detection:** Analyses potential paths through connected infrastructure.
- **Critical Node Detection:** Ranks structurally important assets using graph centrality.
- **AI-Powered Threat Assessment:** Generates threat summaries, identifies affected assets, and recommends security actions.

## Technology Stack
- Frontend: HTML, CSS, JavaScript
- Backend: Google Apps Script
- Database: Neo4j AuraDB
- AI Integration: OpenRouter API with Liquid model

## How It Works
1. Network infrastructure data is stored in Neo4j.
2. THREATSCAPE retrieves graph data from the database.
3. Graph analysis identifies compromised assets and potential exposure paths.
4. AI analyses the supplied graph information.
5. A threat assessment and recommended mitigation actions are generated.

## Project Status
Hackathon prototype.

## Security Note
API keys and database credentials are stored securely in Google Apps Script Properties and are not included in this repository.
