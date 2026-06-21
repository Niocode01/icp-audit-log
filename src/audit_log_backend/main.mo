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
import Nat64 "mo:base/Nat64";
import Nat8 "mo:base/Nat8";

// Audit Log Canister — production-grade, third-party-verifiable
//
// Features:
// - Secure bootstrap: controller-only, one-time admin_bootstrap().
// - Roles: admin (configuration), writers (logging).
// - Deterministic SHA-256 hash chain.
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
    action_hash : Text;
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

  stable var memory_encrypted : Bool = false;
  stable var user_encrypted : Bool = false;
  // --- Vault de archivos stable vars ---
  stable var vault_files : [Text] = [];      // nombres de archivos
  stable var vault_contents : [Text] = [];   // contenido de archivos
  stable var vault_encrypted : [Bool] = [];  // si está cifrado (AES-256-GCM)
  
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

  public shared(msg) func admin_bootstrap() : async Principal {
    if (
      not Principal.equal(admin, Principal.fromText("aaaaa-aa")) or
      admin_initialized or
      init_sentinel == INITIALIZED_SENTINEL
    ) {
      Debug.trap("Already bootstrapped");
    };
    if (not Principal.isController(msg.caller)) {
      Debug.trap("Unauthorized: bootstrap caller is not a controller");
    };
    admin := msg.caller;
    admin_initialized := true;
    writers := [msg.caller];
    init_sentinel := INITIALIZED_SENTINEL;
    msg.caller;
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

  func requireReader(caller : Principal) : Bool {
    isAdmin(caller) or isWriter(caller);
  };

  // ---- SHA-256 ----

  func add32(a : Nat64, b : Nat64) : Nat64 {
    (a +% b) & 0xffff_ffff;
  };

  func rotateRight32(value : Nat64, amount : Nat64) : Nat64 {
    ((value >> amount) | (value << (32 - amount))) & 0xffff_ffff;
  };

  func sha256(input : Text) : Text {
    let source = Blob.toArray(Text.encodeUtf8(input));
    let bitLength : Nat64 = Nat64.fromNat(source.size()) *% 8;
    let paddedLength = ((source.size() + 9 + 63) / 64) * 64;
    let bytes = Array.init<Nat8>(paddedLength, 0);
    var i : Nat = 0;
    while (i < source.size()) {
      bytes[i] := source[i];
      i += 1;
    };
    bytes[source.size()] := 0x80;
    i := 0;
    while (i < 8) {
      bytes[paddedLength - 1 - i] := Nat8.fromNat(
        Nat64.toNat((bitLength >> Nat64.fromNat(i * 8)) & 0xff)
      );
      i += 1;
    };

    let k : [Nat64] = [
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];
    var h0 : Nat64 = 0x6a09e667;
    var h1 : Nat64 = 0xbb67ae85;
    var h2 : Nat64 = 0x3c6ef372;
    var h3 : Nat64 = 0xa54ff53a;
    var h4 : Nat64 = 0x510e527f;
    var h5 : Nat64 = 0x9b05688c;
    var h6 : Nat64 = 0x1f83d9ab;
    var h7 : Nat64 = 0x5be0cd19;
    var offset : Nat = 0;
    while (offset < paddedLength) {
      let w = Array.init<Nat64>(64, 0);
      i := 0;
      while (i < 16) {
        let p = offset + i * 4;
        w[i] := (Nat64.fromNat(Nat8.toNat(bytes[p])) << 24) |
          (Nat64.fromNat(Nat8.toNat(bytes[p + 1])) << 16) |
          (Nat64.fromNat(Nat8.toNat(bytes[p + 2])) << 8) |
          Nat64.fromNat(Nat8.toNat(bytes[p + 3]));
        i += 1;
      };
      while (i < 64) {
        let x = w[i - 15];
        let y = w[i - 2];
        let s0 = rotateRight32(x, 7) ^ rotateRight32(x, 18) ^ (x >> 3);
        let s1 = rotateRight32(y, 17) ^ rotateRight32(y, 19) ^ (y >> 10);
        w[i] := add32(add32(add32(w[i - 16], s0), w[i - 7]), s1);
        i += 1;
      };
      var a = h0; var b = h1; var c = h2; var d = h3;
      var e = h4; var f = h5; var g = h6; var h = h7;
      i := 0;
      while (i < 64) {
        let s1 = rotateRight32(e, 6) ^ rotateRight32(e, 11) ^ rotateRight32(e, 25);
        let ch = (e & f) ^ (((^e) & 0xffff_ffff) & g);
        let temp1 = add32(add32(add32(add32(h, s1), ch), k[i]), w[i]);
        let s0 = rotateRight32(a, 2) ^ rotateRight32(a, 13) ^ rotateRight32(a, 22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = add32(s0, maj);
        h := g; g := f; f := e; e := add32(d, temp1);
        d := c; c := b; b := a; a := add32(temp1, temp2);
        i += 1;
      };
      h0 := add32(h0, a); h1 := add32(h1, b); h2 := add32(h2, c); h3 := add32(h3, d);
      h4 := add32(h4, e); h5 := add32(h5, f); h6 := add32(h6, g); h7 := add32(h7, h);
      offset += 64;
    };

    var out : Text = "";
    for (word in [h0, h1, h2, h3, h4, h5, h6, h7].vals()) {
      var shift : Nat = 28;
      loop {
        out #= hexDigit(Nat64.toNat((word >> Nat64.fromNat(shift)) & 0x0f));
        if (shift == 0) { break };
        shift -= 4;
      };
    };
    out;
  };

  func hexDigit(n : Nat) : Text {
    Text.fromChar(switch (n) {
      case (0) { '0' }; case (1) { '1' }; case (2) { '2' }; case (3) { '3' };
      case (4) { '4' }; case (5) { '5' }; case (6) { '6' }; case (7) { '7' };
      case (8) { '8' }; case (9) { '9' }; case (10) { 'a' }; case (11) { 'b' };
      case (12) { 'c' }; case (13) { 'd' }; case (14) { 'e' }; case _ { 'f' };
    });
  };

  func hashPayload(e : LogEntry) : Text {
    Nat.toText(e.index) # "|" # Int.toText(e.timestamp_ns) # "|" #
    encodeField(e.agent_id) # encodeField(e.action_type) # encodeField(e.action_hash) #
    encodeField(e.metadata) # encodeField(e.caller_hash) # encodeField(e.prev_hash);
  };

  func encodeField(value : Text) : Text {
    Nat.toText(Text.encodeUtf8(value).size()) # ":" # value;
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

    let unsignedEntry : LogEntry = {
      index;
      timestamp_ns = timestamp;
      agent_id;
      action_type;
      action_hash;
      caller_hash;
      prev_hash;
      entry_hash = "";
      metadata;
      caller = caller;
    };
    let entry_hash : Text = sha256(hashPayload(unsignedEntry));
    let entry = { unsignedEntry with entry_hash };

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

      let unsignedEntry : LogEntry = {
        index;
        timestamp_ns = timestamp;
        agent_id;
        action_type;
        action_hash;
        caller_hash;
        prev_hash;
        entry_hash = "";
        metadata;
        caller = caller;
      };
      let entry_hash : Text = sha256(hashPayload(unsignedEntry));
      let entry = { unsignedEntry with entry_hash };

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

  // Encrypted format: "ENC:v1:base64_nonce:base64_ciphertext:base64_tag"
  // Plaintext: just the raw text (backward compatible)
  public shared(msg) func save_profile(memory_text : Text, user_text : Text) : async Bool {
    if (not requireWriter(msg.caller)) { Debug.trap("Unauthorized: not writer"); };
    if (frozen) { Debug.trap("Canister is frozen"); };
    memory_encrypted := Text.startsWith(memory_text, #text "ENC:");
    user_encrypted := Text.startsWith(user_text, #text "ENC:");
    memory_backup := memory_text;
    user_backup := user_text;
    true;
  };
\n\n  public shared(msg) func upload_file(filename : Text, content : Text) : async Nat {
    if (not requireWriter(msg.caller)) { Debug.trap("Unauthorized: not writer"); };
    if (frozen) { Debug.trap("Canister is frozen"); };
    // Check limits: max 100 files, max 10KB per content
    if (vault_files.size() >= 100) {
      Debug.trap("Vault quota exceeded: max 100 files"); // TODO: improve error handling
    };
    let size = content.size();
    if (size > 10 * 1024) {
      Debug.trap("File too large: max 10KB"); // TODO: improve error handling
    };
    // Find if filename already exists
    let mut index : Nat = 0;
    let mut found : Bool = false;
    loop (index < vault_files.size()) {
      if (vault_files[index] == filename) {
        found := true;
        break;
      };
      index := index + 1;
    };
    if (found) {
      // Overwrite existing file
      vault_contents[index] := content;
      // Encryption placeholder: assume not encrypted for simplicity
      vault_encrypted[index] := false;
    } else {
      // Append new file
      vault_files := vault_files.push(filename);
      vault_contents := vault_contents.push(content);
      vault_encrypted := vault_encrypted.push(false); // Encryption placeholder
      index := vault_files.size() - 1; // index of newly added
    };
    index;
  };
\n\n  public shared(msg) func admin_freeze() : async Bool {
  public shared(msg) func admin_freeze() : async Bool {
    if (not requireAdmin(msg.caller)) { Debug.trap("Unauthorized: not admin"); };
    if (frozen) { return false; };
    frozen := true;
    true;
  };

  // ---- Read (protected queries) ----

  public shared query(msg) func get_entry(index : Nat) : async ?LogEntry {
    if (not requireReader(msg.caller)) { Debug.trap("Unauthorized: not admin/writer"); };
    getEntry(index);
  };

  public shared query(msg) func get_total_count() : async Nat {
    if (not requireReader(msg.caller)) { Debug.trap("Unauthorized: not admin/writer"); };
    next_index;
  };

  public shared query(msg) func verify_entry(index : Nat, expected_hash : Text) : async Bool {
    if (not requireReader(msg.caller)) { Debug.trap("Unauthorized: not admin/writer"); };
    switch (getEntry(index)) {
      case (?e) { e.entry_hash == expected_hash and e.entry_hash == sha256(hashPayload(e)) };
      case null { false };
    };
  };

  public shared query(msg) func verify_chain() : async (Bool, Text, Nat, Nat) {
    if (not requireReader(msg.caller)) { Debug.trap("Unauthorized: not admin/writer"); };
    let (valid, broken_at, gen, total) = verifyChainInternal();
    let broken : Text = if (not valid) { Nat.toText(Int.abs(broken_at)) } else { "" };
    (valid, broken, gen, total);
  };

  func verifyChainInternal() : (Bool, Int, Nat, Nat) {
    let total = next_index;
    if (total == 0) {
      return (true, -1, chain_genesis, total);
    };
    var idx : Nat = 0;
    while (idx < total) {
      switch (getEntry(idx)) {
        case (?e) {
          if (e.entry_hash != sha256(hashPayload(e))) {
            return (false, -idx, chain_genesis, total);
          };
          if (idx == 0) {
            if (e.prev_hash != "genesis") {
              return (false, -idx, chain_genesis, total);
            };
          } else {
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
        };
        case null {
          return (false, -idx, chain_genesis, total);
        };
      };
      idx += 1;
    };
    (true, -1, chain_genesis, total);
  };

  public shared query(msg) func get_recent_entries(limit : Nat) : async [LogEntry] {
    if (not requireReader(msg.caller)) { Debug.trap("Unauthorized: not admin/writer"); };
    let capped = if (limit > 1000) { 1000 } else { limit };
    let start = if (next_index > capped) { next_index - capped } else { 0 };
    sliceEntries(start, capped);
  };

  public shared query(msg) func get_all_entries() : async [LogEntry] {
    if (not requireReader(msg.caller)) { Debug.trap("Unauthorized: not admin/writer"); };
    if (next_index > 2000) {
      Debug.trap("Too many entries; use pagination");
    };
    sliceEntries(0, 2000);
  };

  public shared query(msg) func get_entries_by_agent(agent_id : Text) : async [LogEntry] {
    if (not requireReader(msg.caller)) { Debug.trap("Unauthorized: not admin/writer"); };
    let all = sliceEntries(0, 2000);
    Array.filter<LogEntry>(all, func(e : LogEntry) : Bool {
      e.agent_id == agent_id
    });
  };

  public shared query(msg) func get_entries_by_type(action_type : Text) : async [LogEntry] {
    if (not requireReader(msg.caller)) { Debug.trap("Unauthorized: not admin/writer"); };
    let all = sliceEntries(0, 2000);
    Array.filter<LogEntry>(all, func(e : LogEntry) : Bool {
      e.action_type == action_type
    });
  };

  public shared query(msg) func get_recent_entries_paginated(page : Nat, per_page : Nat) : async [LogEntry] {
    if (not requireReader(msg.caller)) { Debug.trap("Unauthorized: not admin/writer"); };
    let p = if (page < 1) { 1 } else { page };
    let pp = if (per_page < 1 or per_page > 500) { 100 } else { per_page };
    let start = (p - 1) * pp;
    sliceEntries(start, pp);
  };

  public query func get_file(filename : Text) : async ?Text {
    let idx = Array.findIndex<Text>(vault_files, func(name : Text) : Bool { name == filename });
    switch (idx) {
      case (?i) { return ?vault_contents[i]; }
      case null { return null; }
    };
  }

  public query func get_file_info(filename : Text) : async ?(Bool, Nat) {
    let idx = Array.findIndex<Text>(vault_files, func(name : Text) : Bool { name == filename });
    switch (idx) {
      case (?i) { return ?(vault_encrypted[i], vault_contents[i].size()); }
      case null { return null; }
    };
  }

  public query func list_vault() : async [Text] {
    return vault_files;
  }

  public shared(msg) func delete_file(filename : Text) : async Bool {
    if (not requireWriter(msg.caller)) { Debug.trap("Unauthorized: not writer"); };
    if (frozen) { Debug.trap("Canister is frozen"); };
    let idx = Array.findIndex<Text>(vault_files, func(name : Text) : Bool { name == filename });
    switch (idx) {
      case (?i) {
        vault_files := Array.remove(vault_files, i);
        vault_contents := Array.remove(vault_contents, i);
        vault_encrypted := Array.remove(vault_encrypted, i);
        return true;
      }
      case null { return false; }
    };
  }


  // ---- JSON helpers ----

  func jsonEscape(s : Text) : Text {
    var result : Text = "";
    for (c in s.chars()) {
      if (c == Char.fromNat32(92)) {
        result #= "\\\\";
      } else if (c == Char.fromNat32(34)) {
        result #= "\\\"";
      } else if (c == Char.fromNat32(47)) {
        result #= "\\/";
      } else if (c == Char.fromNat32(10)) {
        result #= "\\n";
      } else if (c == Char.fromNat32(13)) {
        result #= "\\r";
      } else if (c == Char.fromNat32(9)) {
        result #= "\\t";
      } else if (Char.toNat32(c) < 32) {
        let n = Nat32.toNat(Char.toNat32(c));
        result #= "\\u00" # hexDigit(n / 16) # hexDigit(n % 16);
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
    json #= ",\"action_hash\":\"" # jsonEscape(e.action_hash) # "\"";
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
        ("Referrer-Policy", "no-referrer"),
        ("X-Content-Type-Options", "nosniff"),
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

    if (path == "/api/profile") {
      if (not checkReadAuth(req)) {
        return respond(401, "application/json", "{\"error\":\"Unauthorized\"}");
      };
      let json = "{" #
        "\"memory\":\"" # jsonEscape(memory_backup) # "\"," #
        "\"memory_encrypted\":" # (if memory_encrypted "true" else "false") # "," #
        "\"user\":\"" # jsonEscape(user_backup) # "\"," #
        "\"user_encrypted\":" # (if user_encrypted "true" else "false") #
        "}";
      return respond(200, "application/json", json);
    };

    // --- API: vault upload ---
    if (path == "/api/vault/upload" and req.method == "POST") {
      if (read_token == "" and not checkReadAuth(req)) {
        return respond(401, "application/json", "{\"error\":\"Unauthorized\"}");
      };
      // En implementación real, parsear JSON del body: {filename, content, encrypt}
      // Por ahora, respuesta placeholder para testing
      return respond(200, "application/json", "{\"message\":\"Vault upload endpoint ready\"}");
    };

    // --- API: vault file ---
    if (path == "/api/vault/file" and req.method == "GET") {
      if (read_token == "" and not checkReadAuth(req)) {
        return respond(401, "application/json", "{\"error\":\"Unauthorized\"}");
      };
      // Obtener parámetro 'name' de query string
      switch (urlParam(req.url, "name")) {
        case (?filename) {
          switch (get_file(filename)) {
            case (?content) {
              return respond(200, "text/plain", content);
            };
            case null {
              return respond(404, "application/json", "{\"error\":\"File not found\"}");
            };
          };
        };
        case null {
          return respond(400, "application/json", "{\"error\":\"Missing 'name' parameter\"}");
        };
      };
    };

    // --- API: vault list ---
    if (path == "/api/vault/list" and req.method == "GET") {
      if (read_token == "" and not checkReadAuth(req)) {
        return respond(401, "application/json", "{\"error\":\"Unauthorized\"}");
      };
      switch (list_vault()) {
        case files {
          var json = "{\"files\":[";
          var first = true;
          for (f in files.vals()) {
            if (not first) { json #= ","; };
            json #= "\"" # f # "\"";
            first := false;
          };
          json #= "],\"count\":" # Nat.toText(files.size()) # "}";
          return respond(200, "application/json", json);
        };
      };
    };
    if (path == "/memory") {
      if (not checkReadAuth(req)) {
        return respond(401, "application/json", "{\"error\":\"Unauthorized\"}");
      };
      return respond(200, "text/html; charset=utf-8", MEMORY_PAGE_HTML);
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

  func htmlEscape(s : Text) : Text {
    var result : Text = "";
    for (c in s.chars()) {
      let n = Char.toNat32(c);
      if (n == 38) { result #= "&amp;" }
      else if (n == 60) { result #= "&lt;" }
      else if (n == 62) { result #= "&gt;" }
      else if (n == 34) { result #= "&quot;" }
      else if (n == 39) { result #= "&#39;" }
      else { result #= Text.fromChar(c) };
    };
    result;
  };

  // ---- Dashboard & Memory pages ----

  transient let MEMORY_PAGE_HTML : Text = "<!DOCTYPE html>\n<html lang='en'>\n<head>\n<meta charset='UTF-8'>\n<meta name='viewport' content='width=device-width, initial-scale=1.0'>\n<title>Memory Backup</title>\n<style>\n  body { margin:0; background:#0a0e14; color:#c8d6e5; font-family:monospace; }\n  header { padding:16px 24px; border-bottom:1px solid #1e2836; display:flex; justify-content:space-between; align-items:center; }\n  h1 { font-size:18px; color:#39bae6; margin:0; }\n  a { color:#39bae6; text-decoration:none; }\n  a:hover { text-decoration:underline; }\n  .container { padding:24px; max-width:900px; margin:0 auto; }\n  .section { margin-bottom:32px; }\n  .section h2 { font-size:14px; color:#5c6e84; text-transform:uppercase; border-bottom:1px solid #1e2836; padding-bottom:8px; margin-bottom:12px; display:flex; justify-content:space-between; align-items:baseline; }\n  .badge { font-size:11px; padding:2px 8px; border-radius:3px; }\n  .badge.plain { background:#1e2836; color:#5c6e84; }\n  .badge.encrypted { background:#3a1f1f; color:#f26d78; }\n  .badge.decrypted { background:#1f3a1f; color:#7fd962; }\n  .badge.error { background:#3a2f1f; color:#ffb454; }\n  pre { background:#0d1117; border:1px solid #1e2836; border-radius:4px; padding:16px; font-size:12px; overflow-x:auto; white-space:pre-wrap; word-wrap:break-word; color:#c8d6e5; max-height:60vh; overflow-y:auto; margin:0; }\n  .back-link { font-size:12px; }\n  .empty { color:#5c6e84; font-style:italic; }\n  .token-input { margin-bottom:16px; display:flex; gap:8px; }\n  .token-input input { flex:1; background:#0d1117; border:1px solid #1e2836; color:#c8d6e5; padding:8px 12px; font:12px monospace; border-radius:4px; }\n  .token-input button { background:#131820; color:#c8d6e5; border:1px solid #1e2836; padding:8px 16px; border-radius:4px; font:12px monospace; cursor:pointer; }\n  .token-input button:hover { background:#1e2836; }\n</style>\n</head>\n<body>\n<header>\n  <h1>Memory Backup</h1>\n  <a href='/' class='back-link'>← Back to Dashboard</a>\n</header>\n<div class='container'>\n  <div id='token-section' class='token-input' style='display:none'>\n    <input id='token-field' type='password' placeholder='Enter read token to decrypt profiles...'>\n    <button onclick='decryptWithToken()'>🔓 Decrypt</button>\n  </div>\n  <div class='section'>\n    <h2>Agent Memory <span id='mem-badge' class='badge'></span></h2>\n    <pre id='mem-content'><span class='empty'>Loading...</span></pre>\n  </div>\n  <div class='section'>\n    <h2>User Profile <span id='user-badge' class='badge'></span></h2>\n    <pre id='user-content'><span class='empty'>Loading...</span></pre>\n  </div>\n</div>\n<script>\nvar TOKEN = new URLSearchParams(window.location.search).get('token') || '';\nvar profileData = null;\n\nfunction base64ToBytes(b64) {\n  b64 = b64.replace(/-/g, '+').replace(/_/g, '/');\n  var bin = atob(b64);\n  var bytes = new Uint8Array(bin.length);\n  for (var i = 0; i < bin.length; i++) { bytes[i] = bin.charCodeAt(i); }\n  return bytes;\n}\n\nasync function deriveKey(token) {\n  var data = new TextEncoder().encode(token + 'nebulock-profile-v1');\n  var hash = await crypto.subtle.digest('SHA-256', data);\n  return crypto.subtle.importKey('raw', hash.slice(0, 32), 'AES-GCM', false, ['decrypt']);\n}\n\nasync function decryptProfile(encrypted, token) {\n  var parts = encrypted.split(':');\n  if (parts.length < 5 || parts[0] !== 'ENC' || parts[1] !== 'v1') {\n    throw new Error('Invalid encrypted format');\n  }\n  var nonce = base64ToBytes(parts[2]);\n  var ciphertext = base64ToBytes(parts[3]);\n  var tag = base64ToBytes(parts[4]);\n  var key = await deriveKey(token);\n  var combined = new Uint8Array(ciphertext.length + tag.length);\n  combined.set(ciphertext);\n  combined.set(tag, ciphertext.length);\n  var decrypted = await crypto.subtle.decrypt({name:'AES-GCM', iv:nonce}, key, combined);\n  return new TextDecoder().decode(decrypted);\n}\n\nfunction showTokenInput() {\n  document.getElementById('token-section').style.display = 'flex';\n}\n\nasync function decryptWithToken() {\n  TOKEN = document.getElementById('token-field').value.trim();\n  if (TOKEN) { await renderProfile(); }\n}\n\nasync function loadProfile() {\n  var headers = {};\n  if (TOKEN) { headers['Authorization'] = 'Bearer ' + TOKEN; }\n  try {\n    var res = await fetch('/api/profile', {headers:headers});\n    if (!res.ok) { throw new Error('HTTP ' + res.status); }\n    profileData = await res.json();\n    await renderProfile();\n  } catch(e) {\n    document.getElementById('mem-content').textContent = 'Failed to load profile: ' + e.message;\n  }\n}\n\nasync function renderProfile() {\n  if (!profileData) { return; }\n  var needToken = false;\n\n  // Memory\n  var memPre = document.getElementById('mem-content');\n  var memBadge = document.getElementById('mem-badge');\n  if (profileData.memory) {\n    if (profileData.memory_encrypted) {\n      if (!TOKEN) {\n        memPre.textContent = '🔒 This profile is encrypted. Enter the read token below to decrypt.';\n        memBadge.textContent = '🔒 Encrypted';\n        memBadge.className = 'badge encrypted';\n        needToken = true;\n      } else {\n        try {\n          var plain = await decryptProfile(profileData.memory, TOKEN);\n          memPre.textContent = plain;\n          memBadge.textContent = '🔓 Decrypted';\n          memBadge.className = 'badge decrypted';\n        } catch(e) {\n          memPre.textContent = 'Decryption failed: ' + e.message;\n          memBadge.textContent = '❌ Error';\n          memBadge.className = 'badge error';\n        }\n      }\n    } else {\n      memPre.textContent = profileData.memory;\n      memBadge.textContent = '📄 Plaintext';\n      memBadge.className = 'badge plain';\n    }\n  } else {\n    memPre.innerHTML = '<span class=\"empty\">(empty)</span>';\n    memBadge.textContent = '';\n    memBadge.className = 'badge';\n  }\n\n  // User\n  var userPre = document.getElementById('user-content');\n  var userBadge = document.getElementById('user-badge');\n  if (profileData.user) {\n    if (profileData.user_encrypted) {\n      if (!TOKEN) {\n        userPre.textContent = '🔒 This profile is encrypted. Enter the read token below to decrypt.';\n        userBadge.textContent = '🔒 Encrypted';\n        userBadge.className = 'badge encrypted';\n        needToken = true;\n      } else {\n        try {\n          var plain = await decryptProfile(profileData.user, TOKEN);\n          userPre.textContent = plain;\n          userBadge.textContent = '🔓 Decrypted';\n          userBadge.className = 'badge decrypted';\n        } catch(e) {\n          userPre.textContent = 'Decryption failed: ' + e.message;\n          userBadge.textContent = '❌ Error';\n          userBadge.className = 'badge error';\n        }\n      }\n    } else {\n      userPre.textContent = profileData.user;\n      userBadge.textContent = '📄 Plaintext';\n      userBadge.className = 'badge plain';\n    }\n  } else {\n    userPre.innerHTML = '<span class=\"empty\">(empty)</span>';\n    userBadge.textContent = '';\n    userBadge.className = 'badge';\n  }\n\n  if (needToken) { showTokenInput(); }\n}\n\nwindow.addEventListener('DOMContentLoaded', loadProfile);\n</script>\n</body>\n</html>";

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
    el.className = 'chain-status ok';
    el.textContent = '✓ Chain valid — entries: ' + data.total_entries;
  } else {
    el.className = 'chain-status err';
    el.textContent = '✗ Chain broken at index ' + (data.broken_at || '?');
  }
}
async function loadStats() {
  const data = await getJSON('/api/stats');
  const el = document.getElementById('stats');
  if (!data) {
    el.textContent = 'Failed to load stats';
    return;
  }
  el.textContent = 'Total: ' + data.total + ' | Agents: ' + (data.agents || []).join(', ') + ' | Types: ' + (data.types || []).join(', ');
  const af = document.getElementById('agent-filter');
  af.replaceChildren(new Option('All agents', ''));
  (data.agents || []).forEach(function(a) {
    const o = document.createElement('option');
    o.value = a; o.textContent = a;
    af.appendChild(o);
  });
  const tf = document.getElementById('type-filter');
  tf.replaceChildren(new Option('All types', ''));
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
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 6;
    td.textContent = 'Failed to load entries';
    tr.appendChild(td);
    tbody.replaceChildren(tr);
    return;
  }
  tbody.replaceChildren();
  pageInfo.textContent = 'Page ' + data.pagination.page + ' of ' + data.pagination.total_pages;
  for (const e of data.entries) {
    const tr = document.createElement('tr');
    appendCell(tr, e.index);
    appendCell(tr, e.agent_id);
    appendCell(tr, e.action_type);
    appendHashCell(tr, e.entry_hash);
    appendHashCell(tr, e.prev_hash);
    appendCell(tr, e.timestamp_ms || e.timestamp_ns);
    tbody.appendChild(tr);
  }
}
function appendCell(row, value) {
  const td = document.createElement('td');
  td.textContent = value == null ? '' : String(value);
  row.appendChild(td);
}
function appendHashCell(row, value) {
  const td = document.createElement('td');
  const text = value == null ? '' : String(value);
  td.textContent = text;
  td.title = text;
  td.style.cssText = 'font-size:10px;color:#5c6e84;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;';
  row.appendChild(td);
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