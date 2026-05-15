
import Time "mo:base/Time";
import Array "mo:base/Array";
import Text "mo:base/Text";
import Hash "mo:base/Hash";
import Principal "mo:base/Principal";
import Buffer "mo:base/Buffer";
import Nat "mo:base/Nat";
import Int "mo:base/Int";
import Iter "mo:base/Iter";
import Blob "mo:base/Blob";

persistent actor AuditLog {

  // --- Types ---
  
  type LogEntry = {
    index: Nat;
    timestamp: Int;
    agent_id: Text;
    action_type: Text;
    action_hash: Text;
    metadata: Text;
    caller: Principal;
  };

  type HttpRequest = {
    method: Text;
    url: Text;
    headers: [(Text, Text)];
    body: [Nat8];
  };

  type HttpResponse = {
    status_code: Nat16;
    headers: [(Text, Text)];
    body: [Nat8];
  };

  // --- Stable State ---

  stable var entries: [LogEntry] = [];
  stable var next_index: Nat = 0;

  // --- Write (append-only) ---

  public shared(msg) func log_action(
    agent_id: Text,
    action_type: Text, 
    action_hash: Text,
    metadata: Text
  ) : async Nat {
    let entry: LogEntry = {
      index = next_index;
      timestamp = Time.now();
      agent_id = agent_id;
      action_type = action_type;
      action_hash = action_hash;
      metadata = metadata;
      caller = msg.caller;
    };
    
    entries := Array.append(entries, [entry]);
    next_index += 1;
    
    return entry.index;
  };

  public shared(msg) func log_batch(batch: [(Text, Text, Text, Text)]) : async [Nat] {
    let buf = Buffer.Buffer<Nat>(batch.size());
    for ((agent_id, action_type, action_hash, metadata) in batch.vals()) {
      let entry: LogEntry = {
        index = next_index;
        timestamp = Time.now();
        agent_id = agent_id;
        action_type = action_type;
        action_hash = action_hash;
        metadata = metadata;
        caller = msg.caller;
      };
      entries := Array.append(entries, [entry]);
      buf.add(next_index);
      next_index += 1;
    };
    return Buffer.toArray(buf);
  };

  // --- Read (public queries) ---

  public query func get_entry(index: Nat) : async ?LogEntry {
    if (index < entries.size()) {
      return ?entries[index];
    };
    return null;
  };

  public query func get_all_entries() : async [LogEntry] {
    return entries;
  };

  public query func get_entries_by_agent(agent_id: Text) : async [LogEntry] {
    return Array.filter(entries, func(e: LogEntry) : Bool {
      e.agent_id == agent_id
    });
  };

  public query func get_entries_by_type(action_type: Text) : async [LogEntry] {
    return Array.filter(entries, func(e: LogEntry) : Bool {
      e.action_type == action_type
    });
  };

  public query func get_total_count() : async Nat {
    return entries.size();
  };

  public query func get_recent_entries(limit: Nat) : async [LogEntry] {
    let size = entries.size();
    if (size == 0) return [];
    let start = if (limit > size) { 0 } else { size - limit };
    let buf = Buffer.Buffer<LogEntry>(0);
    var i = start;
    while (i < size) {
      buf.add(entries[i]);
      i += 1;
    };
    return Buffer.toArray(buf);
  };

  public query func verify_entry(index: Nat, expected_hash: Text) : async Bool {
    if (index < entries.size()) {
      return entries[index].action_hash == expected_hash;
    };
    return false;
  };

  public query func get_hash_chain() : async [Text] {
    return Array.map(entries, func(e: LogEntry) : Text { e.action_hash });
  };

  // --- JSON helpers ---

  func jsonEscape(s: Text) : Text {
    var result = "";
    for (c in s.chars()) {
      let ch = Text.fromChar(c);
      if (ch == "\"") { result #= "\\\""; }
      else if (ch == "\\") { result #= "\\\\"; }
      else if (ch == "\n") { result #= "\\n"; }
      else if (ch == "\r") { result #= "\\r"; }
      else if (ch == "\t") { result #= "\\t"; }
      else { result #= ch; };
    };
    return result;
  };

  func entryToJson(e: LogEntry, add_comma: Bool) : Text {
    let ts_ns = Int.toText(e.timestamp);
    let ts_ms = Int.div(e.timestamp, 1_000_000);
    var json = "{\"index\":" # Nat.toText(e.index);
    json #= ",\"agent_id\":\"" # jsonEscape(e.agent_id) # "\"";
    json #= ",\"action_type\":\"" # jsonEscape(e.action_type) # "\"";
    json #= ",\"action_hash\":\"" # e.action_hash # "\"";
    // metadata is already JSON — embed directly
    json #= ",\"metadata\":" # e.metadata;
    json #= ",\"timestamp_ns\":" # ts_ns;
    json #= ",\"timestamp_ms\":" # Int.toText(ts_ms);
    json #= ",\"caller\":\"" # Principal.toText(e.caller) # "\"";
    json #= "}";
    if (add_comma) { json #= ","; };
    return json;
  };

  // --- HTTP Routing ---

  func urlPath(url: Text) : Text {
    // Extract path before '?'
    var path = "";
    for (c in url.chars()) {
      if (Text.fromChar(c) == "?") { return path; };
      path #= Text.fromChar(c);
    };
    return path;
  };

  func urlParam(url: Text, key: Text) : ?Text {
    // Extract ?key=value from URL
    let parts = Iter.toArray(Text.split(url, #text "?"));
    if (parts.size() < 2) return null;
    let qs = parts[1];
    for (pair in Text.split(qs, #text "&")) {
      let kv = Iter.toArray(Text.split(pair, #text "="));
      if (kv.size() == 2 and kv[0] == key) {
        return ?kv[1];
      };
    };
    return null;
  };

  func respond(status: Nat16, contentType: Text, body: Text) : HttpResponse {
    {
      status_code = status;
      headers = [
        ("Content-Type", contentType),
        ("Access-Control-Allow-Origin", "*"),
      ];
      body = Blob.toArray(Text.encodeUtf8(body));
    }
  };

  public query func http_request(req: HttpRequest) : async HttpResponse {
    let path = urlPath(req.url);

    // Serve dashboard HTML (multiple paths to bypass cache)
    if (path == "/" or path == "/index.html" or path == "/dashboard" or path == "/app") {
      return respond(200, "text/html; charset=utf-8", DASHBOARD_HTML);
    };

    // API: entries (paginated)
    if (path == "/api/entries") {
      let entries_list = entries;
      let total = entries_list.size();
      let per_page : Nat = 200;
      
      var page : Nat = 1;
      switch (urlParam(req.url, "page")) {
        case (?p) {
          switch (Nat.fromText(p)) {
            case (?n) { page := n; };
            case null {};
          };
        };
        case null {};
      };
      
      let total_pages = if (total == 0) { 1 } else { (total + per_page - 1) / per_page };
      if (page < 1) { page := 1; };
      if (page > total_pages) { page := total_pages; };
      
      let start = (page - 1) * per_page;
      let end = if (start + per_page > total) { total } else { start + per_page };
      
      // Build paginated JSON
      var json = "{";
      json #= "\"entries\":[";
      var i = start;
      var first = true;
      while (i < end) {
        if (not first) { json #= ","; };
        json #= entryToJson(entries_list[i], false);
        first := false;
        i += 1;
      };
      json #= "],";
      json #= "\"pagination\":{";
      json #= "\"page\":" # Nat.toText(page) # ",";
      json #= "\"per_page\":" # Nat.toText(per_page) # ",";
      json #= "\"total\":" # Nat.toText(total) # ",";
      json #= "\"total_pages\":" # Nat.toText(total_pages) # ",";
      json #= "\"has_next\":" # (if (page < total_pages) { "true" } else { "false" }) # ",";
      json #= "\"has_prev\":" # (if (page > 1) { "true" } else { "false" });
      json #= "}}";
      
      return respond(200, "application/json", json);
    };

    // API: stats
    if (path == "/api/stats") {
      let agents_buf = Buffer.Buffer<Text>(0);
      let types_buf = Buffer.Buffer<Text>(0);
      
      for (e in entries.vals()) {
        // Collect unique agents
        var found = false;
        for (a in agents_buf.vals()) {
          if (a == e.agent_id) { found := true; };
        };
        if (not found) { agents_buf.add(e.agent_id); };
        
        // Collect unique types
        found := false;
        for (t in types_buf.vals()) {
          if (t == e.action_type) { found := true; };
        };
        if (not found) { types_buf.add(e.action_type); };
      };
      
      var json = "{";
      json #= "\"total\":" # Nat.toText(entries.size()) # ",";
      json #= "\"agents\":[";
      var fi = true;
      for (a in agents_buf.vals()) {
        if (not fi) { json #= ","; };
        json #= "\"" # jsonEscape(a) # "\"";
        fi := false;
      };
      json #= "],";
      json #= "\"types\":[";
      fi := true;
      for (t in types_buf.vals()) {
        if (not fi) { json #= ","; };
        json #= "\"" # jsonEscape(t) # "\"";
        fi := false;
      };
      json #= "],";
      json #= "\"canister\":\"s7oui-qqaaa-aaaag-ayx2a-cai\"";
      json #= "}";
      
      return respond(200, "application/json", json);
    };

    // 404
    return respond(404, "text/plain", "Not Found");
  };

  // --- Embedded Dashboard (minified HTML) ---
  
let DASHBOARD_HTML = "<!DOCTYPE html>\n<html lang=\"es\">\n<head>\n<meta charset=\"UTF-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n<title>Nebulock Audit Log v2</title>\n<style>\n  :root {\n    --bg: #0a0e14; --surface: #131820; --border: #1e2836;\n    --text: #c8d6e5; --muted: #5c6e84; --accent: #39bae6;\n    --green: #7fd962; --yellow: #ffb454; --red: #f26d78; --purple: #d2a6ff;\n  }\n  * { margin:0; padding:0; box-sizing:border-box; }\n  body { background:var(--bg); color:var(--text); font-family:monospace; min-height:100vh; }\n  header { background:var(--surface); border-bottom:1px solid var(--border); padding:20px 32px; display:flex; justify-content:space-between; }\n  header h1 { font-size:18px; color:var(--accent); }\n  .canister { font-size:12px; color:var(--muted); }\n  .controls { padding:16px 32px; display:flex; gap:12px; flex-wrap:wrap; border-bottom:1px solid var(--border); background:var(--surface); }\n  .controls select, .controls button, .controls input { background:var(--bg); color:var(--text); border:1px solid var(--border); padding:8px 14px; border-radius:6px; font:13px monospace; }\n  .controls button { background:var(--accent); color:var(--bg); border:none; font-weight:600; cursor:pointer; }\n  .stats { display:flex; gap:24px; padding:16px 32px; font-size:13px; color:var(--muted); }\n  .stats b { color:var(--accent); }\n  table { width:100%; border-collapse:collapse; }\n  th { text-align:left; padding:12px 32px; font-size:11px; text-transform:uppercase; color:var(--muted); border-bottom:1px solid var(--border); }\n  td { padding:10px 32px; font-size:13px; border-bottom:1px solid var(--border); vertical-align:top; }\n  tr:hover td { background:var(--surface); }\n  .badge { display:inline-block; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:600; }\n  .bt { background:#1a2733; color:var(--accent); }\n  .bl { background:#1a2e1a; color:var(--green); }\n  .bs { background:#2e2a1a; color:var(--yellow); }\n  .bu { background:#1a1a2e; color:var(--purple); }\n  .bd { background:#2e1a1a; color:var(--red); }\n  .hash { font-size:11px; color:var(--muted); }\n  .meta { font-size:11px; color:var(--muted); max-width:300px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }\n  .time { font-size:12px; color:var(--muted); white-space:nowrap; }\n  .empty { text-align:center; padding:60px; color:var(--muted); }\n  .loading { text-align:center; padding:40px; }\n  @keyframes spin { to { transform:rotate(360deg); } }\n  .spinner { animation:spin 1s infinite; display:inline-block; }\n  .pagination { display:flex; gap:8px; align-items:center; justify-content:center; padding:16px; flex-wrap:wrap; }\n  .pagination button { background:var(--surface); color:var(--text); border:1px solid var(--border); padding:8px 16px; border-radius:6px; cursor:pointer; font:13px monospace; }\n  .pagination button:hover { background:var(--accent); color:var(--bg); }\n  .pagination button.on { background:var(--accent); color:var(--bg); font-weight:600; }\n  .pagination button:disabled { opacity:0.3; cursor:default; }\n  .pagination span { font-size:12px; color:var(--muted); }\n  footer { text-align:center; padding:16px; font-size:11px; color:var(--muted); border-top:1px solid var(--border); }\n  footer a { color:var(--accent); text-decoration:none; }\n</style>\n</head>\n<body>\n<header>\n  <div>\n    <h1>Nebulock Audit Log</h1>\n    <div style=\"font-size:12px;color:var(--muted);margin-top:4px\">Append-only | Immutable | ICP Mainnet</div>\n  </div>\n  <div class=\"canister\" style=\"text-align:right\">Canister<br><span style=\"color:var(--accent)\">s7oui-qqaaa-aaaag-ayx2a-cai</span></div>\n</header>\n<div class=\"controls\">\n  <select id=\"fa\" onchange=\"loadPage(1)\"><option value=\"\">All agents</option></select>\n  <select id=\"ft\" onchange=\"loadPage(1)\"><option value=\"\">All types</option></select>\n  <input id=\"q\" placeholder=\"Search metadata...\" oninput=\"render()\">\n  <button onclick=\"loadPage(currentPage)\">Refresh</button>\n  <span style=\"font-size:12px;color:var(--muted);margin-left:auto\" id=\"as\">Auto: 1h</span>\n</div>\n<div class=\"stats\">\n  <div>Total: <b id=\"st\">-</b></div>\n  <div>Showing: <b id=\"ss\">-</b></div>\n  <div>Last: <b id=\"sl\">-</b></div>\n</div>\n<table>\n  <thead><tr><th style=\"width:60px\">#</th><th style=\"width:110px\">Agent</th><th style=\"width:140px\">Type</th><th>Hash</th><th>Metadata</th><th style=\"width:160px\">Timestamp</th></tr></thead>\n  <tbody id=\"tb\"><tr><td colspan=\"6\" class=\"loading\"><span class=\"spinner\">*</span> Loading from IC mainnet...</td></tr></tbody>\n</table>\n<div class=\"pagination\" id=\"pg\"></div>\n<footer>\n  <a href=\"https://dashboard.internetcomputer.org/canister/s7oui-qqaaa-aaaag-ayx2a-cai\" target=\"_blank\">IC Dashboard</a>\n  |\n  <a href=\"https://a4gq6-oaaaa-aaaab-qaa4q-cai.raw.ic0.app/?id=s7oui-qqaaa-aaaag-ayx2a-cai\" target=\"_blank\">Candid UI</a>\n</footer>\n<script>\nvar PP=200,CP=1,TP=1,TE=0,entries=[],AR=true;\nfunction bc(t){if(!t)return'bs';if(t.indexOf('tool')===0)return'bt';if(t.indexOf('llm')>=0)return'bl';if(t.indexOf('session')>=0)return'bs';if(t.indexOf('deploy')>=0)return'bd';return'bu';}\nfunction fmt(ms){var d=new Date(ms);return d.toLocaleString('es-ES',{day:'2-digit',month:'2-digit',year:'numeric',hour:'2-digit',minute:'2-digit',second:'2-digit'});}\nfunction mp(m){if(!m)return'-';if(m.content_preview)return m.content_preview.substring(0,80);if(m.tool)return 'T: '+m.tool;if(m.session)return 'S: '+m.session;if(typeof m==='string')return m.substring(0,80);return JSON.stringify(m).substring(0,80);}\nfunction es(s){var d=document.createElement('div');d.textContent=s;return d.innerHTML;}\n\nasync function loadPage(p){\n  try{\n    var r=await fetch('/api/entries?page='+p);\n    if(!r.ok)throw new Error('HTTP '+r.status);\n    var d=await r.json();\n    entries=d.entries;CP=d.pagination.page;TP=d.pagination.total_pages;TE=d.pagination.total;\n    if(p===1){\n      var sr=await fetch('/api/stats');\n      var sd=await sr.json();\n      document.getElementById('fa').innerHTML='<option value=\"\">All agents</option>'+sd.agents.map(function(a){return'<option>'+a+'</option>';}).join('');\n      document.getElementById('ft').innerHTML='<option value=\"\">All types</option>'+sd.types.map(function(t){return'<option>'+t+'</option>';}).join('');\n    }\n    render();\n  }catch(e){\n    document.getElementById('tb').innerHTML='<tr><td colspan=\"6\" class=\"empty\">Error: '+e.message+'</td></tr>';\n  }\n}\n\nfunction goPage(p){if(p<1||p>TP)return;CP=p;loadPage(p);window.scrollTo(0,0);}\n\nfunction renderPagination(){\n  var pg=document.getElementById('pg');\n  if(TP<=1){pg.innerHTML='';return;}\n  var h='';\n  h+='<button onclick=\"goPage('+(CP-1)+')\" '+(CP<=1?'disabled':'')+'>Prev</button> ';\n  var ms=Math.max(1,CP-3),me=Math.min(TP,CP+3);\n  if(ms>1){h+='<button onclick=\"goPage(1)\">1</button>';if(ms>2)h+='<span>...</span>';}\n  for(var i=ms;i<=me;i++)h+='<button onclick=\"goPage('+i+')\" class=\"'+(i===CP?'on':'')+'\">'+i+'</button>';\n  if(me<TP){if(me<TP-1)h+='<span>...</span>';h+='<button onclick=\"goPage('+TP+')\">'+TP+'</button>';}\n  h+=' <button onclick=\"goPage('+(CP+1)+')\" '+(CP>=TP?'disabled':'')+'>Next</button>';\n  h+=' <span>'+CP+' / '+TP+' - '+TE+' total</span>';\n  pg.innerHTML=h;\n}\n\nfunction render(){\n  var af=document.getElementById('fa').value;\n  var tf=document.getElementById('ft').value;\n  var q=document.getElementById('q').value.toLowerCase();\n  var fl=entries;\n  if(af)fl=fl.filter(function(e){return e.agent_id===af;});\n  if(tf)fl=fl.filter(function(e){return e.action_type===tf;});\n  if(q)fl=fl.filter(function(e){return JSON.stringify(e.metadata||'').toLowerCase().indexOf(q)>=0;});\n  document.getElementById('st').textContent=TE;\n  document.getElementById('ss').textContent=fl.length;\n  if(entries.length>0)document.getElementById('sl').textContent=fmt(entries[0].timestamp_ms);\n  var tb=document.getElementById('tb');\n  if(fl.length===0){tb.innerHTML='<tr><td colspan=\"6\" class=\"empty\">No entries</td></tr>';renderPagination();return;}\n  tb.innerHTML=fl.map(function(e){\n    return'<tr><td>'+e.index+'</td><td><b>'+es(e.agent_id)+'</b></td><td><span class=\"badge '+bc(e.action_type)+'\">'+es(e.action_type)+'</span></td><td class=\"hash\">'+es(e.action_hash)+'</td><td class=\"meta\" title=\"'+es(JSON.stringify(e.metadata||''))+'\">'+es(mp(e.metadata))+'</td><td class=\"time\">'+fmt(e.timestamp_ms)+'</td></tr>';\n  }).join('');\n  renderPagination();\n}\n\nloadPage(1);\nsetInterval(function(){if(AR)loadPage(CP);},3600000);\ndocument.getElementById('q').addEventListener('focus',function(){AR=false;});\ndocument.getElementById('q').addEventListener('blur',function(){AR=true;});\n</script>\n</body>\n</html>\n";

};
