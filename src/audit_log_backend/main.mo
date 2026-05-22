import Time "mo:base/Time";
import Array "mo:base/Array";
import Text "mo:base/Text";
import Principal "mo:base/Principal";
import Buffer "mo:base/Buffer";
import Nat "mo:base/Nat";
import Int "mo:base/Int";
import Iter "mo:base/Iter";
import Blob "mo:base/Blob";
import Debug "mo:base/Debug";

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
  stable var authorized_writers: [Principal] = [];
  stable var read_token: Text = "";
  stable var chain_prev_hashes: [Text] = [];
  stable var chain_genesis: Nat = 0;

  // --- Auth helpers ---

  func isAuthorized(caller: Principal) : Bool {
    for (p in authorized_writers.vals()) {
      if (Principal.equal(p, caller)) { return true; };
    };
    return false;
  };

  func assertAuthorized(caller: Principal) {
    if (authorized_writers.size() == 0) { return; };
    if (not isAuthorized(caller)) { Debug.trap("Unauthorized"); };
  };

  func assertAdmin(caller: Principal) {
    if (authorized_writers.size() == 0) { return; };
    if (not isAuthorized(caller)) { Debug.trap("Unauthorized"); };
  };

  func checkReadAuth(req: HttpRequest) : Bool {
    if (read_token == "") { return true; };
    for ((name, value) in req.headers.vals()) {
      if (name == "Authorization" or name == "authorization") {
        return value == "Bearer " # read_token;
      };
    };
    return false;
  };

  // --- Write (append-only, authorized, hash-chained) ---

  public shared(msg) func log_action(
    agent_id: Text,
    action_type: Text, 
    action_hash: Text,
    metadata: Text
  ) : async Nat {
    assertAuthorized(msg.caller);

    let last_hash = if (entries.size() == 0) { "" } else {
      entries[entries.size() - 1].action_hash;
    };
    chain_prev_hashes := Array.append(chain_prev_hashes, [last_hash]);

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
    assertAuthorized(msg.caller);

    let buf = Buffer.Buffer<Nat>(batch.size());
    for ((agent_id, action_type, action_hash, metadata) in batch.vals()) {
      let last_hash = if (entries.size() == 0) { "" } else {
        entries[entries.size() - 1].action_hash;
      };
      chain_prev_hashes := Array.append(chain_prev_hashes, [last_hash]);
      
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

  // --- Admin methods ---

  public shared(msg) func admin_add_writer(principal: Principal) : async Bool {
    assertAdmin(msg.caller);
    if (isAuthorized(principal)) { return false; };
    let n = authorized_writers.size();
    let new_writers = Array.tabulate<Principal>(n + 1, func(i) {
      if (i < n) { authorized_writers[i] } else { principal };
    });
    authorized_writers := new_writers;
    return true;
  };

  public shared(msg) func admin_remove_writer(principal: Principal) : async Bool {
    assertAdmin(msg.caller);
    if (not isAuthorized(principal)) { return false; };
    if (authorized_writers.size() <= 1) {
      Debug.trap("Cannot remove last writer");
    };
    let filtered = Array.filter<Principal>(authorized_writers, func(p) {
      not Principal.equal(p, principal)
    });
    authorized_writers := filtered;
    return true;
  };

  public shared(msg) func admin_list_writers() : async [Principal] {
    assertAdmin(msg.caller);
    return authorized_writers;
  };

  public shared(msg) func admin_set_read_token(token: Text) : async () {
    assertAdmin(msg.caller);
    read_token := token;
  };

  public shared(msg) func admin_get_read_token() : async Text {
    assertAdmin(msg.caller);
    return read_token;
  };

  public shared(msg) func admin_bootstrap() : async Principal {
    if (authorized_writers.size() != 0) {
      Debug.trap("Already bootstrapped");
    };
    authorized_writers := [msg.caller];
    chain_genesis := entries.size();
    return msg.caller;
  };

  // --- Read (public queries) ---

  public query func get_entry(index: Nat) : async ?LogEntry {
    if (index < entries.size()) { return ?entries[index]; };
    return null;
  };

  public query func get_all_entries() : async [LogEntry] { return entries; };

  public query func get_entries_by_agent(agent_id: Text) : async [LogEntry] {
    return Array.filter(entries, func(e: LogEntry) : Bool { e.agent_id == agent_id });
  };

  public query func get_entries_by_type(action_type: Text) : async [LogEntry] {
    return Array.filter(entries, func(e: LogEntry) : Bool { e.action_type == action_type });
  };

  public query func get_total_count() : async Nat { return entries.size(); };

  public query func get_recent_entries(limit: Nat) : async [LogEntry] {
    let size = entries.size();
    if (size == 0) return [];
    let start = if (limit > size) { 0 } else { size - limit };
    let buf = Buffer.Buffer<LogEntry>(0);
    var i = start;
    while (i < size) { buf.add(entries[i]); i += 1; };
    return Buffer.toArray(buf);
  };

  public query func verify_entry(index: Nat, expected_hash: Text) : async Bool {
    if (index < entries.size()) { return entries[index].action_hash == expected_hash; };
    return false;
  };

  public query func get_hash_chain() : async [Text] {
    return Array.map(entries, func(e: LogEntry) : Text { e.action_hash });
  };

  public query func verify_chain() : async (Bool, ?Nat, Nat, Nat) {
    return verifyChainInternal();
  };

  func verifyChainInternal() : (Bool, ?Nat, Nat, Nat) {
    let gen = chain_genesis;
    let total = entries.size();
    let chain_len = chain_prev_hashes.size();
    
    if (chain_len == 0) { return (true, null, gen, total); };
    
    if (gen == 0) {
      if (chain_prev_hashes[0] != "") { return (false, ?gen, gen, total); };
    } else {
      if (gen > 0 and gen <= total) {
        if (chain_prev_hashes[0] != entries[gen - 1].action_hash) {
          return (false, ?gen, gen, total);
        };
      };
    };
    
    var k : Nat = 1;
    while (k < chain_len) {
      let entry_idx = gen + k;
      if (entry_idx >= total) { return (true, null, gen, total); };
      if (chain_prev_hashes[k] != entries[entry_idx - 1].action_hash) {
        return (false, ?entry_idx, gen, total);
      };
      k += 1;
    };
    
    return (true, null, gen, total);
  };

  public query func get_auth_status() : async (Nat, Bool, Nat) {
    return (authorized_writers.size(), read_token != "", chain_genesis);
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

  func getPrevHash(index: Nat) : Text {
    if (index >= chain_genesis) {
      let offset = index - chain_genesis;
      if (offset < chain_prev_hashes.size()) { return chain_prev_hashes[offset]; };
    };
    return "";
  };

  func entryToJson(e: LogEntry, prev_hash: Text, add_comma: Bool) : Text {
    let ts_ns = Int.toText(e.timestamp);
    let ts_ms = Int.div(e.timestamp, 1_000_000);
    var json = "{\"index\":" # Nat.toText(e.index);
    json #= ",\"agent_id\":\"" # jsonEscape(e.agent_id) # "\"";
    json #= ",\"action_type\":\"" # jsonEscape(e.action_type) # "\"";
    json #= ",\"action_hash\":\"" # e.action_hash # "\"";
    json #= ",\"prev_hash\":\"" # prev_hash # "\"";
    json #= ",\"metadata\":" # e.metadata;
    json #= ",\"timestamp_ns\":" # ts_ns;
    json #= ",\"timestamp_ms\":" # Int.toText(ts_ms);
    json #= ",\"caller\":\"" # Principal.toText(e.caller) # "\"";
    json #= "}";
    if (add_comma) { json #= ","; };
    return json;
  };

  func urlPath(url: Text) : Text {
    var path = "";
    for (c in url.chars()) {
      if (Text.fromChar(c) == "?") { return path; };
      path #= Text.fromChar(c);
    };
    return path;
  };

  func urlParam(url: Text, key: Text) : ?Text {
    let parts = Iter.toArray(Text.split(url, #text "?"));
    if (parts.size() < 2) return null;
    let qs = parts[1];
    for (pair in Text.split(qs, #text "&")) {
      let kv = Iter.toArray(Text.split(pair, #text "="));
      if (kv.size() == 2 and kv[0] == key) { return ?kv[1]; };
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

  // --- HTTP Routing ---

  public query func http_request(req: HttpRequest) : async HttpResponse {
    let path = urlPath(req.url);

    // Dashboard HTML (always public)
    if (path == "/" or path == "/index.html" or path == "/dashboard" or path == "/app") {
      return respond(200, "text/html; charset=utf-8", DASHBOARD_HTML);
    };

    // API endpoints require auth if read_token is set
    if (Text.contains(path, #text "/api/") and not checkReadAuth(req)) {
      return respond(401, "application/json", "{\"error\":\"Unauthorized — provide ?token=... or Authorization header\"}");
    };

    // --- API: entries (paginated) ---
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
      
      var json = "{";
      json #= "\"entries\":[";
      var i = start;
      var first = true;
      while (i < end) {
        if (not first) { json #= ","; };
        json #= entryToJson(entries_list[i], getPrevHash(i), false);
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

    // --- API: stats ---
    if (path == "/api/stats") {
      let agents_buf = Buffer.Buffer<Text>(0);
      let types_buf = Buffer.Buffer<Text>(0);
      
      for (e in entries.vals()) {
        var found = false;
        for (a in agents_buf.vals()) { if (a == e.agent_id) { found := true; }; };
        if (not found) { agents_buf.add(e.agent_id); };
        
        found := false;
        for (t in types_buf.vals()) { if (t == e.action_type) { found := true; }; };
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

    // --- API: chain verification ---
    if (path == "/api/chain") {
      let (valid, broken, gen, total) = verifyChainInternal();
      var json = "{";
      json #= "\"valid\":" # (if (valid) { "true" } else { "false" }) # ",";
      json #= "\"total_entries\":" # Nat.toText(total) # ",";
      json #= "\"genesis\":" # Nat.toText(gen);
      switch (broken) {
        case (?idx) { json #= ",\"broken_at\":" # Nat.toText(idx); };
        case null {};
      };
      json #= ",\"writers\":" # Nat.toText(authorized_writers.size());
      json #= ",\"read_protected\":" # (if (read_token != "") { "true" } else { "false" });
      json #= "}";
      return respond(200, "application/json", json);
    };

    return respond(404, "text/plain", "Not Found");
  };

  // --- Dashboard HTML (v3 — auth-aware) ---
  // NOTE: This is a 'let' binding in a persistent actor, so its value
  // is stable and cannot change on upgrade. This is correct for a fresh deploy.
  
let DASHBOARD_HTML = "<!DOCTYPE html>\n<html lang=\"es\">\n<head>\n<meta charset=\"UTF-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n<title>Nebulock Audit Log v3</title>\n<style>\n  :root {\n    --bg: #0a0e14; --surface: #131820; --border: #1e2836;\n    --text: #c8d6e5; --muted: #5c6e84; --accent: #39bae6;\n    --green: #7fd962; --yellow: #ffb454; --red: #f26d78; --purple: #d2a6ff;\n  }\n  * { margin:0; padding:0; box-sizing:border-box; }\n  body { background:var(--bg); color:var(--text); font-family:monospace; min-height:100vh; }\n  header { background:var(--surface); border-bottom:1px solid var(--border); padding:20px 32px; display:flex; justify-content:space-between; }\n  header h1 { font-size:18px; color:var(--accent); }\n  .canister { font-size:12px; color:var(--muted); }\n  .controls { padding:16px 32px; display:flex; gap:12px; flex-wrap:wrap; border-bottom:1px solid var(--border); background:var(--surface); }\n  .controls select, .controls button, .controls input { background:var(--bg); color:var(--text); border:1px solid var(--border); padding:8px 14px; border-radius:6px; font:13px monospace; }\n  .controls button { background:var(--accent); color:var(--bg); border:none; font-weight:600; cursor:pointer; }\n  .stats { display:flex; gap:24px; padding:16px 32px; font-size:13px; color:var(--muted); }\n  .stats b { color:var(--accent); }\n  .chain-status { padding:8px 32px; font-size:12px; }\n  .chain-ok { color:var(--green); }\n  .chain-broken { color:var(--red); }\n  .chain-pending { color:var(--yellow); }\n  .locked { background:#1a1a2e; color:var(--purple); padding:8px 32px; font-size:13px; text-align:center; border-bottom:1px solid var(--border); display:none; }\n  .locked a { color:var(--accent); }\n  table { width:100%; border-collapse:collapse; }\n  th { text-align:left; padding:12px 32px; font-size:11px; text-transform:uppercase; color:var(--muted); border-bottom:1px solid var(--border); }\n  td { padding:10px 32px; font-size:13px; border-bottom:1px solid var(--border); vertical-align:top; }\n  tr:hover td { background:var(--surface); }\n  .badge { display:inline-block; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:600; }\n  .bt { background:#1a2733; color:var(--accent); }\n  .bl { background:#1a2e1a; color:var(--green); }\n  .bs { background:#2e2a1a; color:var(--yellow); }\n  .bu { background:#1a1a2e; color:var(--purple); }\n  .bd { background:#2e1a1a; color:var(--red); }\n  .hash { font-size:11px; color:var(--muted); }\n  .prev-hash { font-size:10px; color:var(--muted); opacity:0.6; }\n  .meta { font-size:11px; color:var(--muted); max-width:300px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }\n  .time { font-size:12px; color:var(--muted); white-space:nowrap; }\n  .empty { text-align:center; padding:60px; color:var(--muted); }\n  .loading { text-align:center; padding:40px; }\n  @keyframes spin { to { transform:rotate(360deg); } }\n  .spinner { animation:spin 1s infinite; display:inline-block; }\n  .pagination { display:flex; gap:8px; align-items:center; justify-content:center; padding:16px; flex-wrap:wrap; }\n  .pagination button { background:var(--surface); color:var(--text); border:1px solid var(--border); padding:8px 16px; border-radius:6px; cursor:pointer; font:13px monospace; }\n  .pagination button:hover { background:var(--accent); color:var(--bg); }\n  .pagination button.on { background:var(--accent); color:var(--bg); font-weight:600; }\n  .pagination button:disabled { opacity:0.3; cursor:default; }\n  .pagination span { font-size:12px; color:var(--muted); }\n  footer { text-align:center; padding:16px; font-size:11px; color:var(--muted); border-top:1px solid var(--border); }\n  footer a { color:var(--accent); text-decoration:none; }\n</style>\n</head>\n<body>\n<header>\n  <div>\n    <h1>Nebulock Audit Log</h1>\n    <div style=\"font-size:12px;color:var(--muted);margin-top:4px\">Append-only | Immutable | Hash-Chained | ICP Mainnet</div>\n  </div>\n  <div class=\"canister\" style=\"text-align:right\">Canister<br><span style=\"color:var(--accent)\">s7oui-qqaaa-aaaag-ayx2a-cai</span></div>\n</header>\n<div class=\"chain-status\" id=\"cs\">Initializing...</div>\n<div class=\"locked\" id=\"lk\">This dashboard is <b>read-protected</b>. <a href=\"#\" onclick=\"promptToken()\">Click to unlock</a> or add <code>?token=...</code> to the URL.</div>\n<div class=\"controls\">\n  <select id=\"fa\" onchange=\"loadPage(1)\"><option value=\"\">All agents</option></select>\n  <select id=\"ft\" onchange=\"loadPage(1)\"><option value=\"\">All types</option></select>\n  <input id=\"q\" placeholder=\"Search metadata...\" oninput=\"render()\">\n  <button onclick=\"loadPage(currentPage)\">Refresh</button>\n  <span style=\"font-size:12px;color:var(--muted);margin-left:auto\" id=\"as\">Auto: 1h</span>\n</div>\n<div class=\"stats\">\n  <div>Total: <b id=\"st\">-</b></div>\n  <div>Showing: <b id=\"ss\">-</b></div>\n  <div>Last: <b id=\"sl\">-</b></div>\n</div>\n<table>\n  <thead><tr><th style=\"width:60px\">#</th><th style=\"width:110px\">Agent</th><th style=\"width:140px\">Type</th><th>Hash</th><th>Metadata</th><th style=\"width:160px\">Timestamp</th></tr></thead>\n  <tbody id=\"tb\"><tr><td colspan=\"6\" class=\"loading\"><span class=\"spinner\">*</span> Loading from IC mainnet...</td></tr></tbody>\n</table>\n<div class=\"pagination\" id=\"pg\"></div>\n<footer>\n  <a href=\"https://dashboard.internetcomputer.org/canister/s7oui-qqaaa-aaaag-ayx2a-cai\" target=\"_blank\">IC Dashboard</a>\n  |\n  <a href=\"https://a4gq6-oaaaa-aaaab-qaa4q-cai.raw.ic0.app/?id=s7oui-qqaaa-aaaag-ayx2a-cai\" target=\"_blank\">Candid UI</a>\n</footer>\n<script>\nvar AT=(function(){var m=location.search.match(/[?&]token=([^&]+)/);if(m){sessionStorage.setItem('at',m[1]);return m[1];}return sessionStorage.getItem('at')||'';})();\nfunction af(u){var h={};if(AT)h.Authorization='Bearer '+AT;return fetch(u,{headers:h});}\nfunction promptToken(){var t=prompt('Enter read token:');if(t){AT=t;sessionStorage.setItem('at',t);location.reload();}}\nfunction isLocked(s){if(s===401){document.getElementById('lk').style.display='block';return true;}document.getElementById('lk').style.display='none';return false;}\nvar PP=200,CP=1,TP=1,TE=0,entries=[],AR=true;\nfunction bc(t){if(!t)return'bs';if(t.indexOf('tool')===0)return'bt';if(t.indexOf('llm')>=0)return'bl';if(t.indexOf('session')>=0)return'bs';if(t.indexOf('deploy')>=0)return'bd';return'bu';}\nfunction fmt(ms){var d=new Date(ms);return d.toLocaleString('es-ES',{day:'2-digit',month:'2-digit',year:'numeric',hour:'2-digit',minute:'2-digit',second:'2-digit'});}\nfunction mp(m){if(!m)return'-';if(m.content_preview)return m.content_preview.substring(0,80);if(m.tool)return'T: '+m.tool;if(m.session)return'S: '+m.session;if(typeof m==='string')return m.substring(0,80);return JSON.stringify(m).substring(0,80);}\nfunction es(s){var d=document.createElement('div');d.textContent=s;return d.innerHTML;}\n\nasync function checkChain(){\n  var cs=document.getElementById('cs');\n  try{\n    var r=await af('/api/chain');\n    if(isLocked(r.status))return;\n    var d=await r.json();\n    if(d.valid){\n      if(d.total_entries===0){cs.innerHTML='Chain: <span class=\"chain-ok\">EMPTY</span> | Waiting for entries';}\n      else if(d.genesis===d.total_entries){cs.innerHTML='Chain: <span class=\"chain-ok\">READY</span> | Genesis at #'+d.genesis+' | Waiting for first chained entry | Writers: '+d.writers+(d.read_protected?' | Read: <span class=\"chain-ok\">auth</span>':' | Read: <span class=\"chain-broken\">open</span>');}\n      else{cs.innerHTML='Chain: <span class=\"chain-ok\">VALID</span> | '+d.total_entries+' entries | Genesis: #'+d.genesis+' | Writers: '+d.writers+(d.read_protected?' | Read: <span class=\"chain-ok\">auth</span>':' | Read: <span class=\"chain-broken\">open</span>');}\n    }else{cs.innerHTML='Chain: <span class=\"chain-broken\">BROKEN at entry #'+d.broken_at+'</span> | Total: '+d.total_entries+' | Genesis: #'+d.genesis;}\n  }catch(e){cs.innerHTML='Chain: <span class=\"chain-broken\">Error: '+e.message+'</span>';}\n}\n\nasync function loadPage(p){\n  try{\n    var r=await af('/api/entries?page='+p);\n    if(isLocked(r.status))return;\n    if(!r.ok)throw new Error('HTTP '+r.status);\n    var d=await r.json();\n    entries=d.entries;CP=d.pagination.page;TP=d.pagination.total_pages;TE=d.pagination.total;\n    if(p===1){\n      var sr=await af('/api/stats');\n      if(isLocked(sr.status))return;\n      var sd=await sr.json();\n      document.getElementById('fa').innerHTML='<option value=\"\">All agents</option>'+sd.agents.map(function(a){return'<option>'+a+'</option>';}).join('');\n      document.getElementById('ft').innerHTML='<option value=\"\">All types</option>'+sd.types.map(function(t){return'<option>'+t+'</option>';}).join('');\n    }\n    render();\n  }catch(e){document.getElementById('tb').innerHTML='<tr><td colspan=\"6\" class=\"empty\">Error: '+e.message+'</td></tr>';}\n}\n\nfunction goPage(p){if(p<1||p>TP)return;CP=p;loadPage(p);window.scrollTo(0,0);}\n\nfunction renderPagination(){\n  var pg=document.getElementById('pg');\n  if(TP<=1){pg.innerHTML='';return;}\n  var h='';\n  h+='<button onclick=\"goPage('+(CP-1)+')\" '+(CP<=1?'disabled':'')+'>Prev</button> ';\n  var ms=Math.max(1,CP-3),me=Math.min(TP,CP+3);\n  if(ms>1){h+='<button onclick=\"goPage(1)\">1</button>';if(ms>2)h+='<span>...</span>';}\n  for(var i=ms;i<=me;i++)h+='<button onclick=\"goPage('+i+')\" class=\"'+(i===CP?'on':'')+'\">'+i+'</button>';\n  if(me<TP){if(me<TP-1)h+='<span>...</span>';h+='<button onclick=\"goPage('+TP+')\">'+TP+'</button>';}\n  h+=' <button onclick=\"goPage('+(CP+1)+')\" '+(CP>=TP?'disabled':'')+'>Next</button>';\n  h+=' <span>'+CP+' / '+TP+' - '+TE+' total</span>';\n  pg.innerHTML=h;\n}\n\nfunction render(){\n  var af=document.getElementById('fa').value;\n  var tf=document.getElementById('ft').value;\n  var q=document.getElementById('q').value.toLowerCase();\n  var fl=entries;\n  if(af)fl=fl.filter(function(e){return e.agent_id===af;});\n  if(tf)fl=fl.filter(function(e){return e.action_type===tf;});\n  if(q)fl=fl.filter(function(e){return JSON.stringify(e.metadata||'').toLowerCase().indexOf(q)>=0;});\n  document.getElementById('st').textContent=TE;\n  document.getElementById('ss').textContent=fl.length;\n  if(entries.length>0)document.getElementById('sl').textContent=fmt(entries[0].timestamp_ms);\n  var tb=document.getElementById('tb');\n  if(fl.length===0){tb.innerHTML='<tr><td colspan=\"6\" class=\"empty\">No entries</td></tr>';renderPagination();return;}\n  tb.innerHTML=fl.map(function(e){\n    var ph=e.prev_hash||'';\n    var phDisplay=ph?ph.substring(0,16)+'...':'genesis';\n    return'<tr><td>'+e.index+'</td><td><b>'+es(e.agent_id)+'</b></td><td><span class=\"badge '+bc(e.action_type)+'\">'+es(e.action_type)+'</span></td><td><div class=\"hash\">'+es(e.action_hash.substring(0,16)+'...')+'</div><div class=\"prev-hash\">prev: '+es(phDisplay)+'</div></td><td class=\"meta\" title=\"'+es(JSON.stringify(e.metadata||''))+'\">'+es(mp(e.metadata))+'</td><td class=\"time\">'+fmt(e.timestamp_ms)+'</td></tr>';\n  }).join('');\n  renderPagination();\n}\n\ncheckChain();\nloadPage(1);\nsetInterval(function(){if(AR)loadPage(CP);checkChain();},3600000);\ndocument.getElementById('q').addEventListener('focus',function(){AR=false;});\ndocument.getElementById('q').addEventListener('blur',function(){AR=true;});\n</script>\n</body>\n</html>\n";

};
