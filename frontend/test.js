const fetch = require('node-fetch');

async function run() {
  try {
    const res = await fetch('http://localhost:8000/api/dashboard/summary');
    const data = await res.json();
    console.log("Dashboard:", data.total_incidents !== undefined ? "OK" : "Error");
    
    // Create a session
    const incidentId = data.recent_incidents[0].id;
    console.log("Incident ID:", incidentId);
    
    const sessionRes = await fetch(`http://localhost:8000/api/incidents/${incidentId}/sessions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    });
    const sessionData = await sessionRes.json();
    console.log("Session:", sessionData);
    
    const sessionId = sessionData.session_id;
    
    // Send message
    const chatRes = await fetch(`http://localhost:8000/api/sessions/${sessionId}/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: "Hello" })
    });
    
    if (!chatRes.ok) {
      console.log("Chat error status:", chatRes.status, chatRes.statusText);
      const errText = await chatRes.text();
      console.log("Chat error:", errText);
    } else {
      const chatData = await chatRes.json();
      console.log("Chat response:", chatData);
    }
    
  } catch (e) {
    console.error("Test failed:", e);
  }
}

run();
