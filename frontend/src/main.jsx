import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { io } from "socket.io-client";
import {
  createIdentity,
  loadPrivate,
  encryptPayload,
  decryptPayload,
  digest,
  hashBytes,
  signBytes,
  verifyBytes,
  enc,
  dec,
  b64,
  unb64,
} from "./crypto";
import "./style.css";
const API =
  import.meta.env.VITE_API_URL ||
  `${location.protocol}//${location.hostname}:5000`;
const req = async (path, token, opts = {}) => {
  const r = await fetch(API + path, {
    ...opts,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: "Bearer " + token } : {}),
      ...(opts.headers || {}),
    },
  });
  const x = await r.json();
  if (!r.ok) throw Error(x.error || "Request failed");
  return x;
};
function Auth({ done }) {
  const [mode, setMode] = useState("login"),
    [form, setForm] = useState({}),
    [err, setErr] = useState("");
  const submit = async (e) => {
    e.preventDefault();
    try {
      setErr("");
      let body;
      if (mode === "register") {
        if (form.password !== form.confirm)
          throw Error("Passwords do not match");
        const identity = await createIdentity(form.email, form.password);
        body = {
          ...form,
          publicKey: identity.publicKey,
          signingPublicKey: identity.signingPublicKey,
          privateKeyBackup: identity.backup,
        };
      } else body = { identity: form.identity, password: form.password };
      const x = await req("/api/auth/" + mode, null, {
        method: "POST",
        body: JSON.stringify(body),
      });
      let backup = x.privateKeyBackup;
      if (!backup) {
        const local = localStorage.getItem("sx-key-" + x.user.email);
        if (local) {
          backup = JSON.parse(local);
          await req("/api/auth/key-backup", x.token, {
            method: "POST",
            body: JSON.stringify({ privateKeyBackup: backup }),
          });
          x.privateKeyBackup = backup;
        }
      }
      const priv = await loadPrivate(x.user.email, form.password, backup);
      done({ ...x, priv });
    } catch (e) {
      setErr(e.message);
    }
  };
  return (
    <main className="auth">
      <section>
        <h1>
          SECURE<span>X</span>
        </h1>
        <p>Secure real-time messaging & cryptographic analysis</p>
        <form onSubmit={submit}>
          {mode === "register" && (
            <>
              <input
                placeholder="Username"
                onChange={(e) => setForm({ ...form, username: e.target.value })}
              />
              <input
                placeholder="Email"
                type="email"
                onChange={(e) => setForm({ ...form, email: e.target.value })}
              />
            </>
          )}{" "}
          {mode === "login" && (
            <input
              placeholder="Email or username"
              onChange={(e) => setForm({ ...form, identity: e.target.value })}
            />
          )}
          <input
            type="password"
            placeholder="Password"
            onChange={(e) => setForm({ ...form, password: e.target.value })}
          />
          {mode === "register" && (
            <input
              type="password"
              placeholder="Confirm password"
              onChange={(e) => setForm({ ...form, confirm: e.target.value })}
            />
          )}
          <button>
            {mode === "login" ? "Sign in" : "Create secure account"}
          </button>
          {err && <small>{err}</small>}
        </form>
        <button
          className="link"
          onClick={() => setMode(mode === "login" ? "register" : "login")}
        >
          {mode === "login"
            ? "Need an account? Register"
            : "Already registered? Sign in"}
        </button>
      </section>
    </main>
  );
}
function Lab() {
  const [tab, setTab] = useState("Text Encrypt / Decrypt"), [input, setInput] = useState("SecureX protects this message."), [textRun, setTextRun] = useState(null), [metrics, setMetrics] = useState(null), [hashRun, setHashRun] = useState(null), [signatureRun, setSignatureRun] = useState(null), [imageResult, setImageResult] = useState(null), [bench, setBench] = useState([]), [busy, setBusy] = useState(false);
  const randomBytes = (size) => { const data = new Uint8Array(size); for (let offset = 0; offset < size; offset += 65536) crypto.getRandomValues(data.subarray(offset, Math.min(offset + 65536, size))); return data; };
  const changedBits = (a, b) => { let count = 0; for (let i = 0; i < Math.min(a.length, b.length); i++) { let value = a[i] ^ b[i]; while (value) { count += value & 1; value >>>= 1; } } return count; };
  const changedChars = (a, b) => [...a].filter((char, index) => char !== b[index]).length;
  const aesGcm = async (data) => { const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]), iv = randomBytes(12); let start = performance.now(); const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data), encryptMs = performance.now() - start; start = performance.now(); const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, cipher), decryptMs = performance.now() - start; return { cipher, plain, encryptMs, decryptMs }; };
  const runText = async () => { const data = enc.encode(input || " "), r = await aesGcm(data); setTextRun({ ...r, bytes: data.byteLength, cipherText: b64(r.cipher), plain: dec.decode(r.plain) }); };
  const runMetrics = async () => {
    const original = enc.encode(input || " "), modified = new Uint8Array(original); modified[0] ^= 1;
    const keyA = randomBytes(32), keyB = new Uint8Array(keyA); keyB[0] ^= 1; const iv = new Uint8Array(16);
    const encryptCbc = async (keyBytes, data) => { const key = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-CBC" }, false, ["encrypt"]); return new Uint8Array(await crypto.subtle.encrypt({ name: "AES-CBC", iv }, key, data)); };
    const cipherA = await encryptCbc(keyA, original), cipherPlainChange = await encryptCbc(keyA, modified), cipherKeyChange = await encryptCbc(keyB, original);
    const base64A = b64(cipherA), base64B = b64(cipherPlainChange), totalBits = cipherA.length * 8;
    setMetrics({ original: dec.decode(original), modified: dec.decode(modified), diffusionBits: changedBits(cipherA, cipherPlainChange), confusionBits: changedBits(cipherA, cipherKeyChange), totalBits, diffusionChars: changedChars(base64A, base64B), totalChars: base64A.length, cipherA: base64A.slice(0, 100), cipherB: base64B.slice(0, 100) });
  };
  const runHash = async () => {
    const source = enc.encode(input || " "), changed = enc.encode((input || " ") + "!"), start = performance.now(), digestA = await hashBytes(source), generationMs = performance.now() - start, changedDigest = await hashBytes(changed);
    const seen = new Map(); let collision = null; for (let i = 0; i < 5000 && !collision; i++) { const candidate = `trial-${i}`; const d = await hashBytes(enc.encode(candidate)); const short = d.slice(0, 3); if (seen.has(short) && seen.get(short) !== candidate) collision = { prefix: short, first: seen.get(short), second: candidate, digestOne: await hashBytes(enc.encode(seen.get(short))), digestTwo: d }; else seen.set(short, candidate); }
    setHashRun({ digestA, changedDigest, generationMs, source: input || " ", changed: (input || " ") + "!", collision });
  };
  const runSignature = async () => { const data = enc.encode(input || " "), pair = await crypto.subtle.generateKey({ name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, false, ["sign", "verify"]); let start = performance.now(); const signature = await crypto.subtle.sign({ name: "RSA-PSS", saltLength: 32 }, pair.privateKey, data), generationMs = performance.now() - start; start = performance.now(); const valid = await crypto.subtle.verify({ name: "RSA-PSS", saltLength: 32 }, pair.publicKey, signature, data), verificationMs = performance.now() - start; const altered = new Uint8Array(data); altered[0] ^= 1; const tamperedValid = await crypto.subtle.verify({ name: "RSA-PSS", saltLength: 32 }, pair.publicKey, signature, altered); setSignatureRun({ generationMs, verificationMs, valid, tamperedValid }); };
  const runImage = async (file) => { if (!file) return; const data = await file.arrayBuffer(), r = await aesGcm(data); setImageResult({ ...r, bytes: data.byteLength, name: file.name, original: URL.createObjectURL(file), decrypted: URL.createObjectURL(new Blob([r.plain], { type: file.type })), cipherText: b64(r.cipher) }); };
  const runBench = async () => { setBusy(true); try { const rows = []; for (const bytes of [1024, 10000, 100000, 500000, 1000000]) { const r = await aesGcm(randomBytes(bytes)); rows.push({ bytes, encryptMs: r.encryptMs, decryptMs: r.decryptMs }); } setBench(rows); } finally { setBusy(false); } };
  const chart = (label, accessor, suffix) => { const max = Math.max(...bench.map(accessor), 1); return <article className="chart"><b>{label}</b>{bench.map((row) => <div className="chart-row" key={row.bytes}><span>{row.bytes >= 1000000 ? "1 MB" : row.bytes / 1000 + " KB"}</span><i style={{ width: `${Math.max(3, (accessor(row) / max) * 100)}%` }} /><em>{accessor(row).toFixed(1)}{suffix}</em></div>)}</article>; };
  const tabs = ["Text Encrypt / Decrypt", "Text Metrics", "Text Performance", "Image Encrypt / Decrypt", "Hash Analysis", "Digital Signature"];
  return <section className="page lab"><h2>Security Lab / {tab}</h2><nav className="tabs">{tabs.map((name) => <button className={tab === name ? "active" : ""} onClick={() => setTab(name)} key={name}>{name}</button>)}</nav>
    {tab !== "Image Encrypt / Decrypt" && tab !== "Text Performance" && <textarea value={input} onChange={(event) => setInput(event.target.value)} />}
    {tab === "Text Encrypt / Decrypt" && <><button onClick={runText}>Encrypt and decrypt text</button>{textRun && <><div className="cards"><article><b>{textRun.bytes}</b><small>plaintext bytes</small></article><article><b>{textRun.encryptMs.toFixed(3)} ms</b><small>AES-GCM encryption</small></article><article><b>{textRun.decryptMs.toFixed(3)} ms</b><small>AES-GCM decryption</small></article><article><b>{(textRun.bytes / (textRun.encryptMs / 1000)).toFixed(0)} B/s</b><small>encryption speed</small></article></div><div className="lab-columns"><pre>PLAINTEXT{`\n`}{input}</pre><pre>CIPHERTEXT (Base64){`\n`}{textRun.cipherText}</pre><pre>DECRYPTED PLAINTEXT{`\n`}{textRun.plain}</pre></div></>}</>}
    {tab === "Text Metrics" && <><button onClick={runMetrics}>Run controlled AES metrics</button><p className="note">This is a controlled AES-CBC measurement with the same IV so ciphertexts can be compared. SecureX chat itself uses AES-GCM with a fresh random IV for security.</p>{metrics && <><div className="cards"><article><b>{((metrics.diffusionBits / metrics.totalBits) * 100).toFixed(2)}%</b><small>diffusion: plaintext one-bit change</small></article><article><b>{((metrics.confusionBits / metrics.totalBits) * 100).toFixed(2)}%</b><small>confusion: key one-bit change</small></article><article><b>{((metrics.diffusionBits / metrics.totalBits) * 100).toFixed(2)}%</b><small>avalanche effect (bit level)</small></article><article><b>{((metrics.diffusionChars / metrics.totalChars) * 100).toFixed(2)}%</b><small>changed Base64 ciphertext chars</small></article></div><div className="lab-columns"><pre>Original input{`\n`}{metrics.original}{`\n\n`}One-bit modified input{`\n`}{metrics.modified}</pre><pre>Ciphertext A{`\n`}{metrics.cipherA}</pre><pre>Ciphertext B{`\n`}{metrics.cipherB}{`\n\n`}Target: about 50% changed bits. Character percentage is shown as a measurement, not falsely guaranteed to be 100%.</pre></div></>}</>}
    {tab === "Text Performance" && <><button onClick={runBench} disabled={busy}>{busy ? "Benchmarking…" : "Run AES-GCM performance benchmark"}</button>{bench.length > 0 && <><table><thead><tr><th>Payload</th><th>Encrypt</th><th>Decrypt</th><th>Encrypt speed</th><th>Decrypt speed</th></tr></thead><tbody>{bench.map((row) => <tr key={row.bytes}><td>{row.bytes.toLocaleString()} bytes</td><td>{row.encryptMs.toFixed(2)} ms</td><td>{row.decryptMs.toFixed(2)} ms</td><td>{(row.bytes / (row.encryptMs / 1000)).toFixed(0)} B/s</td><td>{(row.bytes / (row.decryptMs / 1000)).toFixed(0)} B/s</td></tr>)}</tbody></table><div className="charts">{chart("Encryption time", (r) => r.encryptMs, " ms")}{chart("Decryption time", (r) => r.decryptMs, " ms")}{chart("Encryption throughput", (r) => r.bytes / (r.encryptMs / 1000) / 1000, " KB/s")}{chart("Decryption throughput", (r) => r.bytes / (r.decryptMs / 1000) / 1000, " KB/s")}</div></>}</>}
    {tab === "Image Encrypt / Decrypt" && <><input type="file" accept="image/png,image/jpeg" onChange={(event) => runImage(event.target.files[0])} />{imageResult && <><div className="cards"><article><b>{imageResult.bytes}</b><small>image plaintext bytes</small></article><article><b>{imageResult.encryptMs.toFixed(2)} ms</b><small>AES-GCM encryption</small></article><article><b>{imageResult.decryptMs.toFixed(2)} ms</b><small>AES-GCM decryption</small></article></div><div className="previews"><figure><img src={imageResult.original}/><figcaption>Original image</figcaption></figure><figure><img src={imageResult.decrypted}/><figcaption>Decrypted image</figcaption></figure></div><pre>CIPHERTEXT (Base64){`\n`}{imageResult.cipherText.slice(0, 600)}…</pre></>}</>}
    {tab === "Hash Analysis" && <><button onClick={runHash}>Run SHA-256 resistance demonstration</button>{hashRun && <><div className="cards"><article><b>{hashRun.generationMs.toFixed(3)} ms</b><small>SHA-256 generation time</small></article><article><b>256 bits</b><small>digest length</small></article><article><b>{hashRun.collision ? "FOUND" : "NOT FOUND"}</b><small>toy 16-bit-prefix collision only</small></article></div><div className="lab-columns"><pre>PREIMAGE RESISTANCE{`\n`}Input: {hashRun.source}{`\n`}Digest: {hashRun.digestA}{`\n\n`}Given only the digest, recovering this exact input requires infeasible guessing for SHA-256.</pre><pre>SECOND-PREIMAGE RESISTANCE{`\n`}Changed input: {hashRun.changed}{`\n`}Digest: {hashRun.changedDigest}{`\n\n`}The different input produces a different digest; finding another input with the same full digest is infeasible.</pre><pre>COLLISION RESISTANCE{`\n`}{hashRun.collision ? `Toy 16-bit prefix collision:\n${hashRun.collision.first}\n${hashRun.collision.second}\nPrefix: ${hashRun.collision.prefix}\n\nTheir full SHA-256 digests remain different.` : "No toy prefix collision in 5,000 trials."}{`\n\n`}This deliberately short prefix is only a classroom illustration. It is NOT a collision in full SHA-256.</pre></div></>}</>}
    {tab === "Digital Signature" && <><button onClick={runSignature}>Run RSA-PSS signing test</button>{signatureRun && <div className="cards"><article><b>{signatureRun.generationMs.toFixed(2)} ms</b><small>signature generation</small></article><article><b>{signatureRun.verificationMs.toFixed(2)} ms</b><small>signature verification</small></article><article><b>{signatureRun.valid ? "VALID" : "INVALID"}</b><small>original message</small></article><article><b>{signatureRun.tamperedValid ? "VALID" : "INVALID"}</b><small>tampered message (must be invalid)</small></article></div>}<p className="note">Chat stores RSA-PSS signature, generation time, and receiver verification result for every new message from a freshly registered account.</p></>}
  </section>;
}
function Chat({ session }) {
  const [people, setPeople] = useState([]),
    [convos, setConvos] = useState([]),
    [active, setActive] = useState(null),
    [msgs, setMsgs] = useState([]),
    [body, setBody] = useState(""),
    [composeMode, setComposeMode] = useState("text"),
    [selectedFile, setSelectedFile] = useState(null),
    [status, setStatus] = useState("Connecting…"),
    [error, setError] = useState("");
  const socket = useMemo(() => io(API, { auth: { token: session.token } }), []);
  const load = async () =>
    setConvos(await req("/api/conversations", session.token));
  useEffect(() => {
    const onConnect = () => setStatus("Encrypted channel connected");
    const onMessage = (m) => {
      if (String(m.conversation) === String(active?._id))
        setMsgs((x) =>
          x.some((existing) => String(existing._id) === String(m._id))
            ? x
            : [...x, m],
        );
      load();
    };
    const onDeleted = (d) => {
      if (String(d.conversation) === String(active?._id))
        setMsgs((x) =>
          d.everyone
            ? x.map((m) =>
                String(m._id) === String(d.id)
                  ? { ...m, deletedForEveryone: true }
                  : m,
              )
            : x.filter((m) => String(m._id) !== String(d.id)),
        );
      load();
    };
    load();
    socket.on("connect", onConnect);
    socket.on("secure-message", onMessage);
    socket.on("message-deleted", onDeleted);
    return () => {
      socket.off("connect", onConnect);
      socket.off("secure-message", onMessage);
      socket.off("message-deleted", onDeleted);
    };
  }, [active?._id]);
  useEffect(() => () => socket.disconnect(), [socket]);
  useEffect(() => {
    if (active)
      req("/api/conversations/" + active._id + "/messages", session.token).then(
        setMsgs,
      );
  }, [active?._id]);
  const open = async (p) => {
    const c = await req("/api/conversations", session.token, {
      method: "POST",
      body: JSON.stringify({ userId: p._id }),
    });
    setActive(c);
    load();
  };
  const send = async () => {
    try {
      setError("");
      const file = composeMode === "image" ? selectedFile : null;
      if (!active) throw Error("Choose a conversation first");
      if (composeMode === "image" && !file)
        throw Error("Choose an image before sending");
      if (!file && !body.trim()) return;
      const target = active.members.find(
        (x) => String(x._id) !== String(session.user._id),
      );
      if (!target?.publicKey || !session.user.publicKey)
        throw Error("Encryption key unavailable. Re-open the conversation.");
      const bytes = file ? await file.arrayBuffer() : enc.encode(body),
        hashStart = performance.now(),
        hash = await hashBytes(bytes),
        hashMs = performance.now() - hashStart,
        signature = session.priv.signingPrivate
          ? await signBytes(bytes, session.priv.signingPrivate)
          : null,
        t = performance.now(),
        secured = await encryptPayload(bytes, [session.user, target]),
        encryptionMs = performance.now() - t;
      const message = await req(
        "/api/conversations/" + active._id + "/messages",
        session.token,
        {
          method: "POST",
          body: JSON.stringify({
            conversation: active._id,
            kind: file ? "image" : "text",
            encrypted: secured.encrypted,
            wrappedKeys: secured.wrappedKeys,
            metadata: {
              ...(file ? { name: file.name, type: file.type } : {}),
              plainBytes: bytes.byteLength,
              encryptionMs,
              cipherBytes: Math.floor(
                (secured.encrypted.cipher.length * 3) / 4,
              ),
              hash,
              hashMs,
              ...(signature
                ? {
                    signature: signature.signature,
                    signingPublicKey: session.user.signingPublicKey,
                    signatureMs: signature.ms,
                  }
                : {}),
            },
          }),
        },
      );
      message.localTime = performance.now() - t;
      setMsgs((x) => [...x, message]);
      setBody("");
      setSelectedFile(null);
      load();
    } catch (e) {
      setError(e.message);
    }
  };
  const removeMessage = async (m, everyone) => {
    try {
      await req(
        "/api/messages/" + m._id + "?everyone=" + everyone,
        session.token,
        { method: "DELETE" },
      );
      setMsgs((x) =>
        everyone
          ? x.map((item) =>
              String(item._id) === String(m._id)
                ? { ...item, deletedForEveryone: true }
                : item,
            )
          : x.filter((item) => String(item._id) !== String(m._id)),
      );
    } catch (e) {
      setError(e.message);
    }
  };
  const display = async (m) => {
    try {
      const raw = await decryptPayload(m, session.priv, session.user._id);
      return m.kind === "image"
        ? URL.createObjectURL(new Blob([raw], { type: m.metadata.type }))
        : dec.decode(raw);
    } catch {
      return "[INTEGRITY CHECK FAILED]";
    }
  };
  return (
    <section className="chat">
      <aside>
        <h1>
          SECURE<span>X</span>
        </h1>
        <small className="online">? {status}</small>
        <input
          placeholder="Search users"
          onChange={async (e) =>
            setPeople(
              e.target.value
                ? await req(
                    "/api/users?q=" + encodeURIComponent(e.target.value),
                    session.token,
                  )
                : [],
            )
          }
        />
        {people.map((p) => (
          <button className="person" onClick={() => open(p)}>
            {p.username}
            <small>{p.email}</small>
          </button>
        ))}
        <h3>Conversations</h3>
        {convos.map((c) => {
          const p = c.members.find((x) => x._id !== session.user._id);
          return (
            <button className="person" onClick={() => setActive(c)}>
              {p?.username}
            </button>
          );
        })}
      </aside>
      <main>
        {active ? (
          <>
            <header>
              <b>
                {
                  active.members.find((x) => x._id !== session.user._id)
                    ?.username
                }
              </b>
              <small>AES-256-GCM · RSA-OAEP wrapped keys</small>
              {error && <small className="send-error">{error}</small>}
            </header>
            <div className="messages">
              {msgs.map((m) => (
                <Message
                  key={m._id}
                  m={m}
                  mine={String(m.sender) === String(session.user._id)}
                  display={display}
                  remove={removeMessage}
                />
              ))}
            </div>
            <footer className="composer">
              <div className="mode-switch">
                <button
                  className={composeMode === "text" ? "selected" : ""}
                  onClick={() => setComposeMode("text")}
                >
                  Text
                </button>
                <button
                  className={composeMode === "image" ? "selected" : ""}
                  onClick={() => setComposeMode("image")}
                >
                  Image
                </button>
              </div>
              {composeMode === "text" ? (
                <input
                  value={body}
                  onChange={(e) => setBody(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && send()}
                  placeholder="Write an encrypted message…"
                />
              ) : (
                <label className="file-picker">
                  <input
                    type="file"
                    accept="image/png,image/jpeg"
                    onChange={(e) => setSelectedFile(e.target.files[0] || null)}
                  />
                  {selectedFile ? selectedFile.name : "Choose PNG or JPG image"}
                </label>
              )}
              <button onClick={send}>
                Send {composeMode === "image" ? "image" : "text"}
              </button>
            </footer>
          </>
        ) : (
          <div className="empty">
            Search for a registered user to start a secure one-to-one
            conversation.
          </div>
        )}
      </main>
      {active && (
        <SecurityDetails
          message={msgs[msgs.length - 1]}
          session={session}
          conversation={active}
        />
      )}
    </section>
  );
}
function SecurityDetails({ message, session, conversation }) {
  const [result, setResult] = useState(null);
  const sender = conversation?.members?.find(
    (member) => String(member._id) === String(message?.sender),
  );
  useEffect(() => {
    let alive = true;
    setResult(null);
    if (!message || message.deletedForEveryone) return;
    (async () => {
      try {
        const start = performance.now(),
          raw = await decryptPayload(message, session.priv, session.user._id),
          decryptMs = performance.now() - start,
          hashStart = performance.now(),
          hash = await hashBytes(raw),
          hashMs = performance.now() - hashStart,
          signatureStart = performance.now(),
          registeredSigningKey = sender?.signingPublicKey,
          signatureValid = message.metadata?.signature
            ? registeredSigningKey &&
              registeredSigningKey === message.metadata.signingPublicKey
              ? await verifyBytes(raw, message.metadata.signature, registeredSigningKey)
              : false
            : null,
          signatureVerifyMs = performance.now() - signatureStart;
        if (alive)
          setResult({
            decryptMs,
            hash,
            hashMs,
            signatureValid,
            signatureVerifyMs,
          });
      } catch (e) {
        if (alive) setResult({ error: "Integrity verification failed" });
      }
    })();
    return () => {
      alive = false;
    };
  }, [message?._id, sender?.signingPublicKey]);
  if (!message)
    return (
      <aside className="security-panel">
        <h3>Security Details</h3>
        <p>Send or receive a message to view its actual operations.</p>
      </aside>
    );
  const m = message.metadata || {},
    plain = Number(m.plainBytes || 0),
    cipher = Number(m.cipherBytes || 0);
  return (
    <aside className="security-panel">
      <h3>Security Details</h3>
      <p className={result?.error ? "send-error" : "security-ok"}>
        {result?.error
          ? "SECURITY VERIFICATION FAILED"
          : "SECURITY STATUS: Protected"}
      </p>
      <section>
        <b>SENDER · CONFIDENTIALITY</b>
        <small>
          AES-256-GCM · {plain} plaintext bytes · {cipher} ciphertext bytes
        </small>
        <small>{Number.isFinite(m.encryptionMs)
          ? `Encryption: ${m.encryptionMs.toFixed(2)} ms · ${(plain / (m.encryptionMs / 1000)).toFixed(0)} B/s`
          : "Encryption metrics not recorded for this older message"}</small>
        <code>{(message.encrypted?.cipher || "").slice(0, 44)}…</code>
      </section>
      <section>
        <b>SENDER · HASH & SIGNATURE</b>
        <small>
          SHA-256: {m.hash || "Not recorded for this older message"}
        </small>
        <small>
          Hash generation:{" "}
          {Number.isFinite(m.hashMs)
            ? m.hashMs.toFixed(2) + " ms"
            : "Not available for older message"}
        </small>
        <small>
          RSA-PSS + SHA-256 signing:{" "}
          {Number.isFinite(m.signatureMs)
            ? m.signatureMs.toFixed(2) + " ms"
            : "Not available for older message"}
        </small>
        <small>Sender identity key: {sender?.signingPublicKey ? "registered" : "not available for this account"}</small>
      </section>
      <section>
        <b>RECEIVER · INTEGRITY & DECRYPTION</b>
        <small>
          {result?.error
            ? "INVALID"
            : "VALID - AES-GCM authentication tag verified"}
        </small>
        <small>
          Decryption:{" "}
          {result ? result.decryptMs?.toFixed(2) + " ms" : "Verifying…"}
        </small>
        <small>
          Decryption throughput:{" "}
          {result?.decryptMs
            ? (plain / (result.decryptMs / 1000)).toFixed(0) + " B/s"
            : "-"}
        </small>
      </section>
      <section>
        <b>RECEIVER · HASH & SIGNATURE</b>
        <small>SHA-256: {result?.hash || "Verifying…"}</small>
        <small>
          Hash verification:{" "}
          {result?.hash ? (result.hash === m.hash ? "MATCH" : "MISMATCH") : "-"}{" "}
          · {result?.hashMs?.toFixed(2) || "-"} ms
        </small>
        <small>
          RSA-PSS signature:{" "}
          {result?.signatureValid === null
            ? "Not recorded"
            : result?.signatureValid
              ? "VALID"
              : "INVALID"}{" "}
          · verification {result?.signatureVerifyMs?.toFixed(2) || "-"} ms
        </small>
        {m.signature && !sender?.signingPublicKey && (
          <small>Signature cannot be trusted: the sender has no registered signing key.</small>
        )}
      </section>
      <section>
        <b>KEY SECURITY</b>
        <small>
          AES message key is RSA-OAEP wrapped for both users. Private/secret
          keys are never displayed.
        </small>
      </section>
    </aside>
  );
}
function Message({ m, mine, display, remove }) {
  const [value, setValue] = useState("Decrypting encrypted payload…");
  useEffect(() => {
    if (!m.deletedForEveryone) display(m).then(setValue);
  }, [m]);
  return (
    <div className={"message " + (mine ? "mine" : "")}>
      <small>
        {new Date(m.sentAt).toLocaleTimeString()} ·{" "}
        {m.deletedForEveryone ? "deleted" : "verified AES-GCM"}
      </small>
      {m.deletedForEveryone ? (
        <p>
          <i>This message was deleted.</i>
        </p>
      ) : (
        <>
          {m.kind === "image" && value.startsWith("blob:") ? (
            <img src={value} />
          ) : (
            <p>{value}</p>
          )}
          <div className="delete-actions">
            <button onClick={() => remove(m, false)}>Delete for me</button>
            {mine && (
              <button onClick={() => remove(m, true)}>
                Delete for everyone
              </button>
            )}
          </div>
        </>
      )}
      {m.localTime && (
        <small>encrypted + delivered in {m.localTime.toFixed(1)} ms</small>
      )}
    </div>
  );
}
function Unlock({ saved, done, clear }) {
  const [pw, setPw] = useState(""),
    [err, setErr] = useState("");
  const unlock = async (e) => {
    e.preventDefault();
    try {
      done({
        ...saved,
        priv: await loadPrivate(saved.user.email, pw, saved.privateKeyBackup),
      });
    } catch (e) {
      setErr("Unlock failed: " + e.message);
    }
  };
  return (
    <main className="auth">
      <section>
        <h1>
          SECURE<span>X</span>
        </h1>
        <p>
          Your session remains active. Enter the password to unlock your locally
          protected private key.
        </p>
        <form onSubmit={unlock}>
          <input
            type="password"
            placeholder="Password"
            onChange={(e) => setPw(e.target.value)}
          />
          <button>Unlock SecureX</button>
          {err && <small>{err}</small>}
        </form>
        <button className="link" onClick={clear}>
          Use another account
        </button>
      </section>
    </main>
  );
}
function App() {
  const [s, setS] = useState(null),
    [view, setView] = useState("chat"),
    [saved, setSaved] = useState(() => {
      try {
        return JSON.parse(sessionStorage.getItem("sx-session"));
      } catch {
        return null;
      }
    });
  const begin = (x) => {
    const persisted = {
      token: x.token,
      user: x.user,
      privateKeyBackup: x.privateKeyBackup,
    };
    sessionStorage.setItem("sx-session", JSON.stringify(persisted));
    setSaved(null);
    setS(x);
  };
  const logout = () => {
    sessionStorage.removeItem("sx-session");
    setSaved(null);
    setS(null);
  };
  if (!s && saved) return <Unlock saved={saved} done={begin} clear={logout} />;
  if (!s) return <Auth done={begin} />;
  return (
    <>
      <div className="top">
        <button onClick={() => setView("chat")}>Chat</button>
        <button onClick={() => setView("lab")}>Security Lab</button>
        <span>{s.user.username}</span>
        <button onClick={logout}>Logout</button>
      </div>
      {view === "chat" ? <Chat session={s} /> : <Lab />}
    </>
  );
}
createRoot(document.getElementById("root")).render(<App />);




