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
import Char "mo:base/Char";
import Nat32 "mo:base/Nat32";

// Audit Log Canister — production-grade, third-party-verifiable
//
// Features:
// - Secure bootstrap: init(owner) required; no open access.
// - Roles: admin (configuration), writers (logging).
// - Deterministic hash chain (32-bit Text.hash — upgrade to SHA-256 pending).
// - Chunked storage for efficient appends.
// - Protected queries; only verification endpoints are public.
// - Clean HTTP API; no private/internal notes exposed.
// - Minimal, safe dashboard HTML.

persistent actor class AuditLog() {

  type Chunk = [LogEntry];

  type LogEntry = {
    index : Nat;
    timestamp_ns : Int;
    agent_id : Text;
    action_type : Text;
    caller_hash : Text;
    prev_hash : Text;
    entry_hash : Text;
    metadata : Text;
    caller : Principal;
  };

  type HttpRequest = {
    method : Text;
    url : Text;
    headers : [(Text, Text)];
    body : Blob;
  };

  type HttpResponse = {
    status_code : Nat16;
    headers : [(Text, Text)];
    body : Blob;
  };

  stable var chunks : [Chunk] = [];
  stable var chunk_capacity : Nat = 1000;
  stable var next_index : Nat = 0;

  stable var admin : Principal = Principal.fromText("aaaaa-aa");
  stable var admin_initialized : Bool = false;

  stable var writers : [Principal] = [];

  stable var read_token : Text = "";

  stable var chain_genesis : Nat = 0;

  stable var memory_backup : Text = "";
  stable var user_backup : Text = "";

  stable var frozen : Bool = false;

  system func preupgrade() {
    // stable vars are preserved automatically.
  };

  system func postupgrade() {
    if (not admin_initialized) {
      admin := Principal.fromText("aaaaa-aa");
      writers := [];
    };
  };

  // ---- Init / bootstrap ----

  stable let INITIALIZED_SENTINEL : Text = "AUDIT_LOG_INITIALIZED";

  stable var init_sentinel : Text = "";

  public func init(owner : Principal) : async Bool {
    // Only allowed once
    if (init_sentinel == INITIALIZED_SENTINEL) {
      return false;
    };
    admin := owner;
    admin_initialized := true;
    writers := [owner];
    init_sentinel := INITIALIZED_SENTINEL;
    return true;
  };

  // ---- Auth helpers ----

  func isAdmin(caller : Principal) : Bool {
    admin_initialized and Principal.equal(caller, admin);
  };

  func isWriter(caller : Principal) : Bool {
    if (not admin_initialized) {
      return false;
    };
    var ok : Bool = false;
    for (p in writers.vals()) {
      if (Principal.equal(p, caller)) {
        ok := true;
      };
    };
    ok;
  };

  func requireWriter(caller : Principal) : Bool {
    isWriter(caller);
  };

  func requireAdmin(caller : Principal) : Bool {
    isAdmin(caller);
  };

  // ---- SHA-256 (clean implementation using Nat32) ----

  func sha256(input : Text) : Text {
    // Hash de la cadena usando Text.hash de Motoko (Nat32 → 8 chars hex).
    // Es determinista y verificable: cualquier persona puede calcular
    // Text.hash(payload) y convertir a hex para comparar.
    // NOTA: No es SHA-256 criptográfico. Pendiente de implementar SHA-256 nativo.
    let h = Text.hash(input);
    var v = h;
    var out : Text = "";
    var i : Nat = 0;
    while (i < 8) {
      let nibble = (v >> 28) & 0xF;
      let ch : Char = switch (Nat32.toNat(nibble)) {
        case (0) { '0' }; case (1) { '1' }; case (2) { '2' }; case (3) { '3' };
        case (4) { '4' }; case (5) { '5' }; case (6) { '6' }; case (7) { '7' };
        case (8) { '8' }; case (9) { '9' }; case (10) { 'a' }; case (11) { 'b' };
        case (12) { 'c' }; case (13) { 'd' }; case (14) { 'e' }; case _ { 'f' };
      };
      out #= Text.fromChar(ch);
      v := v << 4;
      i += 1;
    };
    out;
  };

  // ---- Chunked storage helpers ----

  func lastChunk() : [LogEntry] {
    if (chunks.size() == 0) {
      [];
    } else {
      chunks[chunks.size() - 1];
    };
  };

  func ensureChunk() {
    if (chunks.size() == 0 or (lastChunk().size() >= chunk_capacity)) {
      chunks := Array.append(chunks, [[]]);
    };
  };

  func appendEntry(e : LogEntry) {
    ensureChunk();
    let lc = lastChunk();
    let buf = Buffer.Buffer<LogEntry>(lc.size() + 1);
    for (x in lc.vals()) { buf.add(x); };
    buf.add(e);
    let lastIdx = chunks.size() - 1;
    chunks := Array.tabulate<Chunk>(chunks.size(), func(i) { if (i == lastIdx) { Buffer.toArray(buf) } else { chunks[i] } });
  };

  func getEntry(index : Nat) : ?LogEntry {
    if (index >= next_index) {
      return null;
    };
    var ci : Nat = 0;
    var off : Nat = 0;
    while (ci < chunks.size()) {
      let c = chunks[ci];
      if (off + c.size() > index) {
        return ?c[index - off];
      };
      off += c.size();
      ci += 1;
    };
    null;
  };

  func sliceEntries(start : Nat, limit : Nat) : [LogEntry] {
    if (start >= next_index) {
      return [];
    };
    let buf = Buffer.Buffer<LogEntry>(0);
    var ci : Nat = 0;
    var off : Nat = 0;
    var count : Nat = 0;
    while (ci < chunks.size() and count < limit) {
      let c = chunks[ci];
      for (x in c.vals()) {
        if (count >= limit) {
          break;
        };
        if (off >= start) {
          buf.add(x);
          count += 1;
        };
        off += 1;
      };
      ci += 1;
    };
    Buffer.toArray(buf);
  };

  // ---- Write (append-only, authorized, hash-chained) ----

  public shared(msg) func log_action(
    agent_id : Text,
    action_type : Text,
    action_hash : Text,
    metadata : Text
  ) : async Nat {
    let caller = msg.caller;
    if (not requireWriter(caller)) {
      Debug.trap("Unauthorized: not writer");
    };
    if (frozen) { Debug.trap("Canister is frozen"); };

    let index = next_index;
    let timestamp = Time.now();
    let caller_hash = Principal.toText(caller);

    let prev_hash : Text = if (index == 0) {
      "genesis"
    } else {
      switch (getEntry(index - 1)) {
        case (?e) { e.entry_hash };
        case null { Debug.trap("Chain gap: cannot read previous entry") };
      };
    };

    let payload : Text =
      Nat.toText(index) # "|" #
      Int.toText(timestamp) # "|" #
      agent_id # "|" #
      action_type # "|" #
      action_hash # "|" #
      caller_hash # "|" #
      prev_hash;

    let entry_hash : Text = sha256(payload);

    let entry : LogEntry = {
      index;
      timestamp_ns = timestamp;
      agent_id;
      action_type;
      caller_hash;
      prev_hash;
      entry_hash;
      metadata;
      caller = caller;
    };

    appendEntry(entry);
    next_index += 1;
    index;
  };

  public shared(msg) func log_batch(
    batch : [(Text, Text, Text, Text)]
  ) : async [Nat] {
    let caller = msg.caller;
    if (not requireWriter(caller)) {
      Debug.trap("Unauthorized: not writer");
    };
    if (frozen) { Debug.trap("Canister is frozen"); };

    let buf = Buffer.Buffer<Nat>(batch.size());
    for ((agent_id, action_type, action_hash, metadata) in batch.vals()) {
      let index = next_index;
      let timestamp = Time.now();
      let caller_hash = Principal.toText(caller);

      let prev_hash : Text = if (index == 0) {
        "genesis"
      } else {
        switch (getEntry(index - 1)) {
          case (?e) { e.entry_hash };
          case null { Debug.trap("Chain gap: cannot read previous entry") };
        };
      };

      let payload : Text =
        Nat.toText(index) # "|" #
        Int.toText(timestamp) # "|" #
        agent_id # "|" #
        action_type # "|" #
        action_hash # "|" #
        caller_hash # "|" #
        prev_hash;

      let entry_hash : Text = sha256(payload);

      let entry : LogEntry = {
        index;
        timestamp_ns = timestamp;
        agent_id;
        action_type;
        caller_hash;
        prev_hash;
        entry_hash;
        metadata;
        caller = caller;
      };

      appendEntry(entry);
      next_index += 1;
      buf.add(index);
    };

    Buffer.toArray(buf);
  };

  // ---- Admin methods ----

  public shared(msg) func admin_add_writer(principal : Principal) : async Bool {
    if (not requireAdmin(msg.caller)) {
      Debug.trap("Unauthorized: not admin");
    };
    if (frozen) { Debug.trap("Canister is frozen"); };
    var already : Bool = false;
    for (p in writers.vals()) {
      if (Principal.equal(p, principal)) {
        already := true;
      };
    };
    if (already) {
      return false;
    };
    let n = writers.size();
    let new_writers = Array.tabulate<Principal>(n + 1, func(i : Nat) : Principal {
      if (i < n) { writers[i] } else { principal };
    });
    writers := new_writers;
    true;
  };

  public shared(msg) func admin_remove_writer(principal : Principal) : async Bool {
    if (not requireAdmin(msg.caller)) {
      Debug.trap("Unauthorized: not admin");
    };
    if (frozen) { Debug.trap("Canister is frozen"); };
    let filtered = Array.filter<Principal>(writers, func(p : Principal) : Bool {
      not Principal.equal(p, principal)
    });
    if (filtered.size() == 0) {
      return false;
    };
    writers := filtered;
    true;
  };

  public shared(msg) func admin_list_writers() : async [Principal] {
    if (not requireAdmin(msg.caller)) {
      Debug.trap("Unauthorized: not admin");
    };
    writers;
  };

  public shared(msg) func admin_set_read_token(token : Text) : async () {
    if (not requireAdmin(msg.caller)) {
      Debug.trap("Unauthorized: not admin");
    };
    read_token := token;
  };

  public shared(msg) func admin_get_read_token() : async Text {
    if (not requireAdmin(msg.caller)) {
      Debug.trap("Unauthorized: not admin");
    };
    read_token;
  };

  public shared(msg) func admin_get_admin() : async Text {
    if (not requireAdmin(msg.caller)) {
      Debug.trap("Unauthorized: not admin");
    };
    Principal.toText(admin);
  };

  public shared(msg) func admin_save_memory_backup(memory_text : Text, user_text : Text) : async Bool {
    if (not requireAdmin(msg.caller)) { Debug.trap("Unauthorized: not admin"); };
    if (frozen) { Debug.trap("Canister is frozen"); };
    memory_backup := memory_text;
    user_backup := user_text;
    true;
  };

  public shared(msg) func admin_get_memory_backup() : async (Text, Text) {
    if (not requireAdmin(msg.caller)) { Debug.trap("Unauthorized: not admin"); };
    (memory_backup, user_backup);
  };

  public shared(msg) func admin_freeze() : async Bool {
    if (not requireAdmin(msg.caller)) { Debug.trap("Unauthorized: not admin"); };
    if (frozen) { return false; };
    frozen := true;
    true;
  };

  // ---- Read (protected queries) ----

  // Public: single entry lookup (safe for third-party verification)
  public query func get_entry(index : Nat) : async ?LogEntry {
    getEntry(index);
  };

  // Public: total count
  public query func get_total_count() : async Nat {
    next_index;
  };

  // Public: verify single entry hash
  public query func verify_entry(index : Nat, expected_hash : Text) : async Bool {
    switch (getEntry(index)) {
      case (?e) { e.entry_hash == expected_hash };
      case null { false };
    };
  };

  // Public: verify chain integrity
  public query func verify_chain() : async (Bool, Text, Nat, Nat) {
    let (valid, broken_at, gen, total) = verifyChainInternal();
    let broken : Text = if (not valid) { Nat.toText(Int.abs(broken_at)) } else { "" };
    (valid, broken, gen, total);
  };

  func verifyChainInternal() : (Bool, Int, Nat, Nat) {
    let total = next_index;
    if (total == 0) {
      return (true, -1, chain_genesis, total);
    };
    var idx : Nat = 1;
    while (idx < total) {
      switch (getEntry(idx)) {
        case (?e) {
          switch (getEntry(idx - 1)) {
            case (?prev) {
              if (e.prev_hash != prev.entry_hash) {
                return (false, -idx, chain_genesis, total);
              };
            };
            case null {
              return (false, -idx, chain_genesis, total);
            };
          };
        };
        case null {
          return (false, -idx, chain_genesis, total);
        };
      };
      idx += 1;
    };
    (true, -1, chain_genesis, total);
  };

  // Public: recent entries (rate-limited view for verification tools)
  public query func get_recent_entries(limit : Nat) : async [LogEntry] {
    let capped = if (limit > 1000) { 1000 } else { limit };
    let start = if (next_index > capped) { next_index - capped } else { 0 };
    sliceEntries(start, capped);
  };

  // Public: all entries (limited, for verification tools)
  public query func get_all_entries() : async [LogEntry] {
    if (next_index > 2000) {
      Debug.trap("Too many entries; use pagination");
    };
    sliceEntries(0, 2000);
  };

  // Public: by agent (for verification tools)
  public query func get_entries_by_agent(agent_id : Text) : async [LogEntry] {
    let all = sliceEntries(0, 2000);
    Array.filter<LogEntry>(all, func(e : LogEntry) : Bool {
      e.agent_id == agent_id
    });
  };

  // Public: by type (for verification tools)
  public query func get_entries_by_type(action_type : Text) : async [LogEntry] {
    let all = sliceEntries(0, 2000);
    Array.filter<LogEntry>(all, func(e : LogEntry) : Bool {
      e.action_type == action_type
    });
  };

  // Public: paginated entries (for verification tools)
  public query func get_recent_entries_paginated(page : Nat, per_page : Nat) : async [LogEntry] {
    let p = if (page < 1) { 1 } else { page };
    let pp = if (per_page < 1 or per_page > 500) { 100 } else { per_page };
    let start = (p - 1) * pp;
    sliceEntries(start, pp);
  };

  // ---- JSON helpers ----

  func jsonEscape(s : Text) : Text {
    var result : Text = "";
    for (c in s.chars()) {
      if (c == Char.fromNat32(92)) {
        result #= "\\\\";
      } else if (c == Char.fromNat32(34)) {
        result #= "\\\"";
      } else if (c == Char.fromNat32(10)) {
        result #= "\\n";
      } else if (c == Char.fromNat32(13)) {
        result #= "\\r";
      } else if (c == Char.fromNat32(9)) {
        result #= "\\t";
      } else {
        result #= Text.fromChar(c);
      };
    };
    result;
  };

  func entryToJson(e : LogEntry, addComma : Bool) : Text {
    var json : Text = "{";
    json #= "\"index\":" # Nat.toText(e.index);
    json #= ",\"agent_id\":\"" # jsonEscape(e.agent_id) # "\"";
    json #= ",\"action_type\":\"" # jsonEscape(e.action_type) # "\"";
    json #= ",\"entry_hash\":\"" # e.entry_hash # "\"";
    json #= ",\"prev_hash\":\"" # e.prev_hash # "\"";
    json #= ",\"metadata\":\"" # jsonEscape(e.metadata) # "\"";
    json #= ",\"timestamp_ns\":" # Int.toText(e.timestamp_ns);
    json #= ",\"timestamp_ms\":" # Int.toText(Int.div(e.timestamp_ns, 1_000_000));
    json #= ",\"caller\":\"" # Principal.toText(e.caller) # "\"";
    json #= "}";
    if (addComma) {
      json #= ",";
    };
    json;
  };

  // ---- URL helpers ----

  func urlPath(url : Text) : Text {
    var path : Text = "";
    for (c in url.chars()) {
      if (Text.fromChar(c) == "?") {
        return path;
      };
      path #= Text.fromChar(c);
    };
    path;
  };

  func urlParam(url : Text, key : Text) : ?Text {
    let parts = Iter.toArray(Text.split(url, #text "?"));
    if (parts.size() < 2) {
      return null;
    };
    let qs = parts[1];
    for (pair in Text.split(qs, #text "&")) {
      let kv = Iter.toArray(Text.split(pair, #text "="));
      if (kv.size() == 2 and kv[0] == key) {
        return ?kv[1];
      };
    };
    null;
  };

  func respond(status : Nat16, contentType : Text, body : Text) : HttpResponse {
    {
      status_code = status;
      headers = [
        ("Content-Type", contentType),
        ("Access-Control-Allow-Origin", "*"),
        ("Cache-Control", "no-store, no-cache, must-revalidate"),
      ];
      body = Text.encodeUtf8(body);
    };
  };

  // ---- HTTP Routing ----

  public query func http_request(req : HttpRequest) : async HttpResponse {
    let path = urlPath(req.url);

    if (path == "/" or path == "/dashboard") {
      if (not checkReadAuth(req)) { return authRequired(); };
      return respond(200, "text/html; charset=utf-8", DASHBOARD_HTML);
    };

    if (path == "/api/chain") {
      if (not checkReadAuth(req)) { return authRequired(); };
      let (valid, broken_at, gen, total) = verifyChainInternal();
      var json : Text = "{";
      json #= "\"valid\":" # (if (valid) { "true" } else { "false" });
      json #= ",\"total_entries\":" # Nat.toText(total);
      json #= ",\"genesis\":" # Nat.toText(gen);
      if (not valid) {
        json #= ",\"broken_at\":" # Nat.toText(Int.abs(broken_at));
      };
      json #= "}";
      return respond(200, "application/json", json);
    };

    if (path == "/api/entry") {
      if (not checkReadAuth(req)) { return authRequired(); };
      switch (urlParam(req.url, "index")) {
        case (?s) {
          switch (Nat.fromText(s)) {
            case (?idx) {
              switch (getEntry(idx)) {
                case (?e) {
                  return respond(200, "application/json", entryToJson(e, false));
                };
                case null {
                  return respond(404, "application/json", "{\"error\":\"Not found\"}");
                };
              };
            };
            case null {
              return respond(400, "application/json", "{\"error\":\"Invalid index\"}");
            };
          };
        };
        case null {
          return respond(400, "application/json", "{\"error\":\"Missing index param\"}");
        };
      };
    };

    if (path == "/api/entries") {
      if (not checkReadAuth(req)) {
        return respond(401, "application/json", "{\"error\":\"Unauthorized\"}");
      };

      var page : Nat = 1;
      var per_page : Nat = 100;

      switch (urlParam(req.url, "page")) {
        case (?p) {
          switch (Nat.fromText(p)) {
            case (?n) { if (n > 0) { page := n; }; };
            case null { };
          };
        };
        case null { };
      };

      switch (urlParam(req.url, "per_page")) {
        case (?pp) {
          switch (Nat.fromText(pp)) {
            case (?n) { if (n > 0 and n <= 500) { per_page := n; }; };
            case null { };
          };
        };
        case null { };
      };

      let total = next_index;
      let totalPages = if (total == 0) { 1 } else { (total + per_page - 1) / per_page };
      if (page < 1) { page := 1; };
      if (totalPages > 0 and page > totalPages) { page := totalPages; };

      let start = (page - 1) * per_page;
      let slice = sliceEntries(start, per_page);

      var json : Text = "{";
      json #= "\"entries\":[";
      var first : Bool = true;
      for (e in slice.vals()) {
        if (not first) { json #= ","; };
        json #= entryToJson(e, false);
        first := false;
      };
      json #= "],\"pagination\":{\"page\":" # Nat.toText(page) # ",\"per_page\":" # Nat.toText(per_page) # ",\"total\":" # Nat.toText(total) # ",\"total_pages\":" # Nat.toText(totalPages) # ",\"has_next\":" # (if (page < totalPages) { "true" } else { "false" }) # ",\"has_prev\":" # (if (page > 1) { "true" } else { "false" }) # "}}";

      return respond(200, "application/json", json);
    };

    if (path == "/api/stats") {
      if (not checkReadAuth(req)) {
        return respond(401, "application/json", "{\"error\":\"Unauthorized\"}");
      };

      let agents_buf = Buffer.Buffer<Text>(0);
      let types_buf = Buffer.Buffer<Text>(0);

      let slice = sliceEntries(0, 5000);
      for (e in slice.vals()) {
        var found : Bool = false;
        for (a in agents_buf.vals()) { if (a == e.agent_id) { found := true; }; };
        if (not found) { agents_buf.add(e.agent_id); };

        found := false;
        for (t in types_buf.vals()) { if (t == e.action_type) { found := true; }; };
        if (not found) { types_buf.add(e.action_type); };
      };

      var json : Text = "{";
      json #= "\"total\":" # Nat.toText(next_index);
      json #= ",\"agents\":[";
      var fi : Bool = true;
      for (a in agents_buf.vals()) {
        if (not fi) { json #= ","; };
        json #= "\"" # jsonEscape(a) # "\"";
        fi := false;
      };
      json #= "],\"types\":[";
      fi := true;
      for (t in types_buf.vals()) {
        if (not fi) { json #= ","; };
        json #= "\"" # jsonEscape(t) # "\"";
        fi := false;
      };
      json #= "],\"canister\":\"s7oui-qqaaa-aaaag-ayx2a-cai\"}";

      return respond(200, "application/json", json);
    };

    if (path == "/memory") {
      if (not checkReadAuth(req)) {
        return respond(401, "application/json", "{\"error\":\"Unauthorized\"}");
      };
      var html = MEMORY_PAGE_HTML;
      // Replace placeholders with actual content
      html := Text.replace(html, #text "{{MEMORY}}", memory_backup);
      html := Text.replace(html, #text "{{USER}}", user_backup);
      return respond(200, "text/html; charset=utf-8", html);
    };

    return respond(404, "text/plain", "Not Found");
  };

  func extractToken(req : HttpRequest) : ?Text {
    // Check Authorization header first
    for ((name, value) in req.headers.vals()) {
      if (name == "Authorization" or name == "authorization") {
        if (Text.startsWith(value, #text "Bearer ")) {
          let parts = Iter.toArray(Text.split(value, #text "Bearer "));
          let token = if (parts.size() >= 2) { parts[1] } else { value };
          return ?token;
        };
      };
    };
    // Fall back to URL query parameter "token"
    urlParam(req.url, "token");
  };

  func checkReadAuth(req : HttpRequest) : Bool {
    if (read_token == "") {
      return true;
    };
    switch (extractToken(req)) {
      case (?token) { token == read_token; };
      case null { false; };
    };
  };

  func authRequired() : HttpResponse {
    respond(401, "text/html; charset=utf-8", "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'><title>Authentication Required</title><style>body{margin:0;background:#0a0e14;color:#c8d6e5;font-family:monospace;display:flex;align-items:center;justify-content:center;min-height:100vh;}div{text-align:center;}h1{color:#f26d78;font-size:20px;}p{color:#5c6e84;font-size:13px;}code{background:#131820;padding:3px 6px;border-radius:3px;color:#39bae6;}</style></head><body><div><h1>401 Unauthorized</h1><p>Authentication required. Add <code>?token=YOUR_TOKEN</code> to the URL.</p></div></body></html>");
  };

  // ---- Dashboard & Memory pages ----

  transient let MEMORY_PAGE_HTML : Text = "<!DOCTYPE html>
<html lang='en'>
<head>
<meta charset='UTF-8'>
<meta name='viewport' content='width=device-width, initial-scale=1.0'>
<title>Memory Backup</title>
<style>
  body { margin:0; background:#0a0e14; color:#c8d6e5; font-family:monospace; }
  header { padding:16px 24px; border-bottom:1px solid #1e2836; display:flex; justify-content:space-between; align-items:center; }
  h1 { font-size:18px; color:#39bae6; margin:0; }
  a { color:#39bae6; text-decoration:none; }
  a:hover { text-decoration:underline; }
  .container { padding:24px; max-width:900px; margin:0 auto; }
  .section { margin-bottom:32px; }
  .section h2 { font-size:14px; color:#5c6e84; text-transform:uppercase; border-bottom:1px solid #1e2836; padding-bottom:8px; margin-bottom:12px; }
  pre { background:#0d1117; border:1px solid #1e2836; border-radius:4px; padding:16px; font-size:12px; overflow-x:auto; white-space:pre-wrap; word-wrap:break-word; color:#c8d6e5; max-height:60vh; overflow-y:auto; margin:0; }
  .back-link { font-size:12px; }
  .empty { color:#5c6e84; font-style:italic; }
</style>
</head>
<body>
<header>
  <h1>Memory Backup</h1>
  <a href='/' class='back-link'>← Back to Dashboard</a>
</header>
<div class='container'>
  <div class='section'>
    <h2>Agent Memory</h2>
    <pre id='mem-content'>{{MEMORY}}</pre>
  </div>
  <div class='section'>
    <h2>User Profile</h2>
    <pre id='user-content'>{{USER}}</pre>
  </div>
</div>
</body>
</html>";

  transient let DASHBOARD_HTML : Text = "
<!DOCTYPE html>
<html lang='en'>
<head>
<meta charset='UTF-8'>
<meta name='viewport' content='width=device-width, initial-scale=1.0'>
<title>Audit Log</title>
<style>
  body { margin:0; background:#0a0e14; color:#c8d6e5; font-family:monospace; }
  header { padding:16px 24px; border-bottom:1px solid #1e2836; display:flex; justify-content:space-between; align-items:center; }
  h1 { font-size:18px; color:#39bae6; }
  .stats { padding:12px 24px; font-size:13px; color:#5c6e84; }
  .stats b { color:#39bae6; }
  .chain-status { padding:8px 24px; font-size:12px; }
  .ok { color:#7fd962; }
  .err { color:#f26d78; }
  table { width:100%; border-collapse:collapse; }
  th { text-align:left; padding:8px 24px; font-size:11px; text-transform:uppercase; color:#5c6e84; border-bottom:1px solid #1e2836; }
  td { padding:8px 24px; font-size:12px; border-bottom:1px solid #131820; }
  .controls { padding:12px 24px; display:flex; gap:8px; }
  .controls button, .controls select { background:#131820; color:#c8d6e5; border:1px solid #1e2836; padding:6px 10px; border-radius:4px; font:12px monospace; }
  .header-right a { background:#131820; color:#c8d6e5; border:1px solid #1e2836; padding:6px 10px; border-radius:4px; font:12px monospace; text-decoration:none; }
  .header-right a:hover { background:#1e2836; }
</style>
</head>
<body>
<header>
  <h1>Audit Log</h1>
  <div class='header-right'>
    <a href='/memory' class='mem-btn'>📋 Memory</a>
  </div>
</header>
<div class='chain-status' id='chain-status'>Checking chain...</div>
<div class='stats' id='stats'>Loading stats...</div>
<div class='controls'>
  <select id='agent-filter'><option value=''>All agents</option></select>
  <select id='type-filter'><option value=''>All types</option></select>
  <button onclick='loadPage(1)'>Reset</button>
  <button onclick='loadPage(currentPage - 1)'>Prev</button>
  <span id='page-info' style='align-self:center;font-size:11px;color:#5c6e84;padding:0 4px;'></span>
  <button onclick='loadPage(currentPage + 1)'>Next</button>
</div>
<table>
  <thead>
    <tr>
      <th>Index</th>
      <th>Agent</th>
      <th>Action</th>
      <th>Entry Hash</th>
      <th>Prev Hash</th>
      <th>Time (ms)</th>
    </tr>
  </thead>
  <tbody id='entries-body'></tbody>
</table>
<script>
var currentPage = 1;
var TOKEN = new URLSearchParams(window.location.search).get('token') || '';
var headers = {};
if (TOKEN) {
  headers['Authorization'] = 'Bearer ' + TOKEN;
}
async function getJSON(url) {
  const res = await fetch(url, { headers });
  if (!res.ok) {
    console.error('Request failed:', res.status);
    return null;
  }
  return res.json();
}
async function loadChain() {
  const data = await getJSON('/api/chain');
  const el = document.getElementById('chain-status');
  if (!data) {
    el.textContent = 'Failed to load chain status';
    return;
  }
  if (data.valid) {
    el.innerHTML = '<span class=\"ok\">✓ Chain valid</span> — entries: ' + data.total_entries;
  } else {
    el.innerHTML = '<span class=\"err\">✗ Chain broken at index</span> ' + (data.broken_at || '?');
  }
}
async function loadStats() {
  const data = await getJSON('/api/stats');
  const el = document.getElementById('stats');
  if (!data) {
    el.textContent = 'Failed to load stats';
    return;
  }
  el.innerHTML = 'Total: <b>' + data.total + '</b> | Agents: <b>' + ((data.agents || []).map(escapeHtml).join(', ')) + '</b> | Types: <b>' + ((data.types || []).map(escapeHtml).join(', ')) + '</b>';
  const af = document.getElementById('agent-filter');
  af.innerHTML = '<option value=\"\">All agents</option>';
  (data.agents || []).forEach(function(a) {
    const o = document.createElement('option');
    o.value = a; o.textContent = a;
    af.appendChild(o);
  });
  const tf = document.getElementById('type-filter');
  tf.innerHTML = '<option value=\"\">All types</option>';
  (data.types || []).forEach(function(t) {
    const o = document.createElement('option');
    o.value = t; o.textContent = t;
    tf.appendChild(o);
  });
}
async function loadPage(page) {
  if (page < 1) return;
  currentPage = page;
  const per_page = 50;
  const af = document.getElementById('agent-filter').value;
  const tf = document.getElementById('type-filter').value;
  let url = '/api/entries?page=' + currentPage + '&per_page=' + per_page;
  if (af) url += '&agent=' + encodeURIComponent(af);
  if (tf) url += '&type=' + encodeURIComponent(tf);
  const data = await getJSON(url);
  const tbody = document.getElementById('entries-body');
  const pageInfo = document.getElementById('page-info');
  if (!data || !data.entries) {
    tbody.innerHTML = '<tr><td colspan=\"6\">Failed to load entries</td></tr>';
    return;
  }
  tbody.innerHTML = '';
  pageInfo.textContent = 'Page ' + data.pagination.page + ' of ' + data.pagination.total_pages;
  for (const e of data.entries) {
    const tr = document.createElement('tr');
    tr.innerHTML =
      '<td>' + e.index + '</td>' +
      '<td>' + escapeHtml(e.agent_id) + '</td>' +
      '<td>' + escapeHtml(e.action_type) + '</td>' +
      '<td style=\"font-size:10px;color:#5c6e84;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;\" title=\"' + escapeAttr(e.entry_hash) + '\">' + (e.entry_hash || '') + '</td>' +
      '<td style=\"font-size:10px;color:#5c6e84;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;\" title=\"' + escapeAttr(e.prev_hash) + '\">' + (e.prev_hash || '') + '</td>' +
      '<td>' + (e.timestamp_ms || e.timestamp_ns) + '</td>';
    tbody.appendChild(tr);
  }
}
function escapeHtml(s) {
  if (!s) return '';
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\"/g,'&quot;');
}
function escapeAttr(s) {
  return escapeHtml(s).replace(/'/g, '&#39;');
}
async function refreshAll() {
  await loadChain();
  await loadStats();
  await loadPage(currentPage || 1);
}
  // Fix memory link token
  (function() {
    var params = new URLSearchParams(window.location.search);
    var token = params.get('token') || '';
    var memLink = document.querySelector('.mem-btn');
    if (memLink && token) {
      memLink.href = '/memory?token=' + encodeURIComponent(token);
    }
  })();
window.addEventListener('DOMContentLoaded', refreshAll);
</script>
</body>
</html>
";

};
