
  
function doGet() {
  return HtmlService
    .createTemplateFromFile('Index')
    .evaluate()
    .setTitle('THREATSCAPE | Cyber Threat Intelligence');
}

function include(filename) {
  return HtmlService
    .createHtmlOutputFromFile(filename)
    .getContent();
}

function testBackend() {
  return {
    status: "success",
    message: "THREATSCAPE online backend is running!"
  };
}

function runNeo4jQuery(statement) {
  const properties = PropertiesService.getScriptProperties();

  const uri = properties.getProperty("NEO4J_URI");
  const username = properties.getProperty("NEO4J_USERNAME");
  const password = properties.getProperty("NEO4J_PASSWORD");
  const database = properties.getProperty("NEO4J_DATABASE") || "neo4j";

  if (!uri || !username || !password) {
    throw new Error("Neo4j connection details are missing from Script Properties.");
  }

  const url = uri.replace(/\/$/, "") +
    "/db/" + encodeURIComponent(database) + "/query/v2";

  const headers = {
    Authorization: "Basic " +
      Utilities.base64Encode(username + ":" + password),
    "Content-Type": "application/json"
  };

  const response = UrlFetchApp.fetch(url, {
    method: "post",
    headers: headers,
    payload: JSON.stringify({ statement: statement }),
    muteHttpExceptions: true
  });

  const status = response.getResponseCode();
  const body = response.getContentText();

  if (status < 200 || status >= 300) {
    throw new Error("Neo4j returned HTTP " + status + ": " + body);
  }

  return JSON.parse(body);
}

function testNeo4jConnection() {
  const result = runNeo4jQuery(
    "MATCH (n) RETURN elementId(n), labels(n), properties(n) LIMIT 20"
  );

  Logger.log(JSON.stringify(result, null, 2));

  return result;
}



function getNeo4jGraph() {
  const result = runNeo4jQuery(
    "MATCH (n) " +
    "OPTIONAL MATCH (n)-[r]->(m) " +
    "RETURN elementId(n) AS sourceId, " +
    "labels(n) AS sourceLabels, " +
    "properties(n) AS sourceProperties, " +
    "type(r) AS relationship, " +
    "elementId(m) AS targetId, " +
    "labels(m) AS targetLabels, " +
    "properties(m) AS targetProperties"
  );

  const rows = result.data.values;

  const nodeMap = {};
  const edges = [];

  rows.forEach(row => {
    const [
      sourceId,
      sourceLabels,
      sourceProperties,
      relationship,
      targetId,
      targetLabels,
      targetProperties
    ] = row;

    nodeMap[sourceId] = {
      id: sourceId,
      labels: sourceLabels,
      properties: sourceProperties
    };

    if (targetId) {
      nodeMap[targetId] = {
        id: targetId,
        labels: targetLabels,
        properties: targetProperties
      };

      edges.push({
        source: sourceId,
        target: targetId,
        type: relationship
      });
    }
  });

  const graphData = {
    nodes: Object.values(nodeMap),
    edges: edges
  };

  Logger.log(JSON.stringify(graphData, null, 2));

  return graphData;
}

function getDashboardGraph() {
  const graph = getNeo4jGraph();

  const nodes = graph.nodes.map(node => ({
    id: node.properties.name,
    type: node.labels[0],
    status: node.properties.status || "Unknown",
    criticality: node.properties.criticality || "Unknown"
  }));

  const nameById = {};

  graph.nodes.forEach(node => {
    nameById[node.id] = node.properties.name;
  });

  const edges = graph.edges.map(edge => [
    nameById[edge.source],
    nameById[edge.target]
  ]);

  return {
    nodes: nodes,
    edges: edges
  };
}

function testDashboardGraph() {
  const result = getDashboardGraph();
  Logger.log(JSON.stringify(result, null, 2));
  return result;
}

// ======================================
// THREATSCAPE - GEMMA 4 CONNECTION TEST
// ======================================

function testOpenRouterAI() {
  const apiKey = PropertiesService
    .getScriptProperties()
    .getProperty("OPENROUTER_API_KEY");

  if (!apiKey) {
    throw new Error("OPENROUTER_API_KEY is missing.");
  }

  const url = "https://openrouter.ai/api/v1/chat/completions";

  const payload = {
    model: "liquid/lfm-2.5-2.6b:free",
    messages: [
      {
        role: "user",
        content: "You are THREATSCAPE's cybersecurity assistant. Explain briefly how AI can help analyze potential cybersecurity threats."
      }
    ],
    max_tokens: 600
  };

  const response = UrlFetchApp.fetch(url, {
    method: "post",
    contentType: "application/json",
    headers: {
      Authorization: "Bearer " + apiKey
    },
    payload: JSON.stringify(payload),
    muteHttpExceptions: true
  });

  const status = response.getResponseCode();
  const result = response.getContentText();

  Logger.log("HTTP Status: " + status);
  Logger.log(result);

  if (status < 200 || status >= 300) {
    throw new Error("OpenRouter request failed. Check execution log.");
  }

  const data = JSON.parse(result);
  Logger.log("THREATSCAPE AI: " +
    data.choices[0].message.content);
}

function generateThreatAssessment() {
  const apiKey = PropertiesService
    .getScriptProperties()
    .getProperty("OPENROUTER_API_KEY");

  if (!apiKey) {
    throw new Error("OpenRouter API key is missing.");
  }

  // Get existing graph data from Neo4j
  const graph = getDashboardGraph();

  if (!graph || !graph.nodes || !graph.edges) {
    throw new Error("Unable to retrieve graph data.");
  }

  const graphData = JSON.stringify(graph);

  const prompt = `
You are THREATSCAPE, a cybersecurity analysis assistant.

Analyze the following infrastructure graph.

GRAPH DATA:
${graphData}

Your tasks:
1. Identify assets marked as compromised.
2. Explain their connections to other assets.
3. Identify potential exposure paths.
4. Highlight critical databases or systems that may be reachable.
5. Suggest practical security mitigation steps.

Important:
- Use only the supplied graph data.
- Do not claim that an actual cyberattack occurred.
- Distinguish potential exposure from confirmed compromise.
- Do not invent missing information.
- Keep the report concise and professional.

Generate the report with these headings:
THREAT SUMMARY
AFFECTED ASSETS
POTENTIAL RISK
RECOMMENDED ACTIONS
`;

  const response = UrlFetchApp.fetch(
    "https://openrouter.ai/api/v1/chat/completions",
    {
      method: "post",
      contentType: "application/json",
      headers: {
        Authorization: "Bearer " + apiKey
      },
      payload: JSON.stringify({
        model: "liquid/lfm-2.5-2.6b:free",
        messages: [
          {
            role: "user",
            content: prompt
          }
        ],
        max_tokens: 800
      }),
      muteHttpExceptions: true
    }
  );

  const status = response.getResponseCode();
  const result = response.getContentText();

  Logger.log("HTTP Status: " + status);

  if (status < 200 || status >= 300) {
    Logger.log(result);
    throw new Error("AI threat analysis failed.");
  }

  const data = JSON.parse(result);
  const report = data.choices[0].message.content;

  if (!report) {
    Logger.log(JSON.stringify(data));
    throw new Error("AI returned no report. Try again.");
  }

  Logger.log("THREATSCAPE AI REPORT:");
  Logger.log(report);

  return report;
}
