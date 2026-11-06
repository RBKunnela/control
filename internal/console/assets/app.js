"use strict";

// Every value from the server is set as text on a node, never parsed as
// markup: a resource id is the agent's own text. Every sentence about a
// record, a listing or a pause file is the server's; this script places them.
(function () {
  var SESSION_KEY = "console-session";
  var REFRESH_MS = 5000;
  // An answer button does nothing for this long after the list changes, so a
  // card that appears or grows cannot put another card's button under a
  // pointer that was already on its way.
  var SETTLE_MS = 1000;

  var session = "";
  var reasons = Object.create(null);
  var cards = Object.create(null);
  var shownPause = "";
  var settleTimer = 0;
  var settling = false;

  // oneLine quotes a value holding a control, format, bidirectional or line
  // separator character, or a replaced byte, so the value cannot reorder or
  // break what is shown around it.
  var QUOTED = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\uFFFD]/u;

  function oneLine(value) {
    var s = String(value);
    if (!QUOTED.test(s)) {
      return s;
    }
    var out = "\"";
    for (var ch of s) {
      var c = ch.codePointAt(0);
      if (ch === "\"" || ch === "\\") {
        out += "\\" + ch;
      } else if (ch === "\n") {
        out += "\\n";
      } else if (ch === "\r") {
        out += "\\r";
      } else if (ch === "\t") {
        out += "\\t";
      } else if (QUOTED.test(ch)) {
        out += c > 0xffff ? "\\U" + hex(c, 8) : "\\u" + hex(c, 4);
      } else {
        out += ch;
      }
    }
    return out + "\"";
  }

  function hex(n, width) {
    var h = n.toString(16);
    while (h.length < width) {
      h = "0" + h;
    }
    return h;
  }

  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) {
      node.className = cls;
    }
    if (text !== undefined) {
      node.textContent = text;
    }
    return node;
  }

  function byId(id) {
    return document.getElementById(id);
  }

  function clear(node) {
    while (node.firstChild) {
      node.removeChild(node.firstChild);
    }
  }

  function lines(box, texts) {
    [].concat(texts).forEach(function (line) {
      box.appendChild(el("p", "", oneLine(line)));
    });
    return box;
  }

  function notice(kind, texts) {
    var box = lines(el("div", "notice " + kind), texts);
    var close = el("button", "dismiss", "Dismiss");
    close.type = "button";
    close.addEventListener("click", function () {
      box.remove();
    });
    box.appendChild(close);
    byId("notices").prepend(box);
  }

  function api(method, path, body, token) {
    var init = {
      method: method,
      headers: { "X-Console-Token": token === undefined ? session : token },
      cache: "no-store",
      credentials: "omit",
      redirect: "error",
      referrerPolicy: "no-referrer"
    };
    if (body !== undefined) {
      init.headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(body);
    }
    return fetch(path, init).then(function (res) {
      return res.json().then(
        function (data) {
          return { ok: res.ok, status: res.status, data: data };
        },
        function () {
          return { ok: false, status: res.status, data: { error: "the answer was not JSON" } };
        }
      );
    });
  }

  function storedSession() {
    try {
      return sessionStorage.getItem(SESSION_KEY) || "";
    } catch (e) {
      return "";
    }
  }

  function keepSession(s) {
    session = s;
    try {
      sessionStorage.setItem(SESSION_KEY, s);
    } catch (e) {
      // Without storage the session lives in this variable until the tab reloads.
    }
  }

  // start trades the token the link carries for a session of this tab. The
  // link stays in the browser's history, and what it carries is spent.
  function start() {
    session = storedSession();
    if (location.hash.indexOf("#t=") !== 0) {
      return Promise.resolve();
    }
    var printed = location.hash.slice(3);
    history.replaceState(null, "", location.pathname + location.search);
    return api("POST", "/api/session", {}, printed).then(function (r) {
      if (r.ok) {
        keepSession(r.data.session);
      } else if (!session) {
        setBanner("The page refused this link: " + oneLine(r.data.error));
      }
    }, unreachable);
  }

  function unreachable() {
    setBanner("The page cannot reach the console command, which may have stopped. What is shown may be out of date.");
  }

  function setBanner(text) {
    var banner = byId("connection");
    if (!text) {
      if (banner) {
        banner.remove();
      }
      return;
    }
    if (!banner) {
      banner = el("div", "notice error");
      banner.id = "connection";
      document.body.insertBefore(banner, byId("notices"));
    }
    banner.textContent = text;
  }

  function load() {
    api("GET", "/api/state").then(function (r) {
      if (!r.ok) {
        setBanner("The page refused this tab: " + oneLine(r.data.error));
        return;
      }
      setBanner("");
      render(r.data);
    }, unreachable);
  }

  function render(state) {
    byId("who").textContent = oneLine(state.who);
    renderApprovals(state.approvals);
    var pause = JSON.stringify(state.pause);
    if (pause !== shownPause) {
      shownPause = pause;
      renderPause(state.pause);
    }
  }

  // renderApprovals keeps every card where it was first put. A record seen
  // again is redrawn in its own card, a new one goes after all of them, and
  // a card whose record has left the directory stays, saying so.
  function renderApprovals(a) {
    byId("dir").textContent = "Directory: " + oneLine(a.directory);
    byId("plane").textContent = oneLine(a.plane);
    var head = byId("listing");
    clear(head);
    if (a.banner.length > 0) {
      head.appendChild(lines(el("div", "notice error"), a.banner));
    }
    if (a.empty && Object.keys(cards).length === 0) {
      head.appendChild(el("p", "empty", oneLine(a.empty)));
    }
    var changed = false;
    var listed = Object.create(null);
    a.records.forEach(function (r) {
      listed[r.approval_id] = true;
      var text = JSON.stringify(r);
      var card = cards[r.approval_id];
      if (!card) {
        card = { node: el("article", "record"), text: "", gone: false };
        cards[r.approval_id] = card;
        byId("records").appendChild(card.node);
      }
      if (card.text !== text || card.gone) {
        card.text = text;
        card.gone = false;
        fillCard(card.node, r);
        changed = true;
      }
    });
    if (!a.error && a.complete) {
      Object.keys(cards).forEach(function (id) {
        var card = cards[id];
        if (!listed[id] && !card.gone) {
          card.gone = true;
          markGone(card.node, a.gone);
          changed = true;
        }
      });
    }
    if (changed) {
      settle();
    }
  }

  function fillCard(card, r) {
    clear(card);
    card.appendChild(el("h3", "", oneLine(r.title)));
    card.appendChild(el("p", "status", oneLine(r.status)));
    var dl = el("dl", "fields");
    r.fields.forEach(function (f) {
      dl.appendChild(el("dt", "", oneLine(f.label)));
      dl.appendChild(el("dd", "", oneLine(f.value)));
    });
    card.appendChild(dl);
    if (r.answerable) {
      card.appendChild(answerControls(r));
    }
  }

  function markGone(card, text) {
    var controls = card.querySelector(".answer");
    if (controls) {
      controls.remove();
    }
    card.appendChild(el("p", "gone", oneLine(text)));
  }

  // settle holds every answer button for SETTLE_MS from the last change.
  function settle() {
    guard(true);
    clearTimeout(settleTimer);
    settleTimer = setTimeout(function () {
      guard(false);
    }, SETTLE_MS);
  }

  function guard(on) {
    settling = on;
    document.querySelectorAll("button.guarded").forEach(function (b) {
      b.disabled = on;
    });
  }

  function answerControls(r) {
    var id = r.approval_id;
    var box = el("div", "answer");
    var label = el("label", "", "Reason (optional)");
    var input = el("input");
    input.type = "text";
    input.maxLength = 1024;
    input.value = reasons[id] || "";
    input.addEventListener("input", function () {
      reasons[id] = input.value;
    });
    label.appendChild(input);
    box.appendChild(label);
    var first = el("div", "choices");
    first.appendChild(button("Approve", "approve guarded", function () {
      confirmStep(box, first, r, "approve");
    }));
    first.appendChild(button("Reject", "reject guarded", function () {
      confirmStep(box, first, r, "reject");
    }));
    box.appendChild(first);
    return box;
  }

  // confirmStep asks once more, naming the call, and binds the answer to the
  // digest it names: the server refuses it for any other record.
  function confirmStep(box, first, r, kind) {
    first.hidden = true;
    var ask = el("div", "confirm");
    var verb = kind === "approve" ? "Approve " : "Reject ";
    ask.appendChild(el("p", "", verb + oneLine(r.confirm) + "?"));
    ask.appendChild(button(kind === "approve" ? "Yes, approve" : "Yes, reject", kind + " guarded", function () {
      answer(kind, r);
    }));
    ask.appendChild(button("Cancel", "cancel", function () {
      ask.remove();
      first.hidden = false;
    }));
    box.appendChild(ask);
  }

  function button(text, cls, onClick) {
    var b = el("button", cls, text);
    b.type = "button";
    b.disabled = settling && cls.indexOf("guarded") >= 0;
    b.addEventListener("click", onClick);
    return b;
  }

  // answer sends the record's own id and digest, and names it as its card
  // does.
  function answer(kind, rec) {
    var id = rec.approval_id;
    api("POST", "/api/" + kind, { id: id, reason: reasons[id] || "", action_digest: rec.action_digest }).then(function (r) {
      if (!r.ok) {
        notice("error", oneLine(rec.title) + " was not answered: " + oneLine(r.data.error));
      } else {
        delete reasons[id];
        notice("info", r.data.notice);
      }
      load();
    }, unreachable);
  }

  function renderPause(p) {
    var box = byId("pause");
    clear(box);
    byId("pause-form").hidden = p === null;
    if (p === null) {
      box.appendChild(el("p", "", "This page was started without a pause file, so it shows and writes no pause."));
      return;
    }
    box.appendChild(el("p", "", "File: " + oneLine(p.file)));
    if (p.state === "unreadable") {
      box.appendChild(lines(el("div", "notice error"), [p.status, p.error]));
      return;
    }
    box.appendChild(el("p", "status", oneLine(p.status)));
    p.entries.forEach(function (e) {
      var row = el("div", "entry");
      row.appendChild(el("p", "", oneLine(e.covers)));
      var dl = el("dl", "fields");
      e.fields.forEach(function (f) {
        dl.appendChild(el("dt", "", oneLine(f.label)));
        dl.appendChild(el("dd", "", oneLine(f.value)));
      });
      row.appendChild(dl);
      row.appendChild(button("Lift this pause", "unpause", function () {
        write("/api/unpause", { id: e.id });
      }));
      box.appendChild(row);
    });
  }

  function write(path, body) {
    api("POST", path, body).then(function (r) {
      notice(r.ok ? "info" : "error", r.ok ? r.data.notice : "Not written: " + oneLine(r.data.error));
      shownPause = "";
      load();
    }, unreachable);
  }

  function pauseForm() {
    var form = el("div", "pause-form");
    form.id = "pause-form";
    form.hidden = true;
    form.appendChild(el("h3", "", "Pause calls"));
    var kind = select("Which calls", [["global", "every call"], ["provider", "every call to one upstream"], ["action", "one kind of call to one upstream"]]);
    var provider = textInput("Upstream, by its configured name", 256);
    var action = select("Kind of call", [["tool", "tool"], ["prompt", "prompt"], ["resource", "resource"]]);
    var name = textInput("Tool name, as the plane routes it", 256);
    var reason = textInput("Reason, for whoever lifts it", 512);
    [kind, provider, action, name, reason].forEach(function (f) {
      form.appendChild(f.label);
    });
    function sync() {
      provider.label.hidden = kind.input.value === "global";
      action.label.hidden = kind.input.value !== "action";
      name.label.hidden = kind.input.value !== "action" || action.input.value !== "tool";
    }
    kind.input.addEventListener("change", sync);
    action.input.addEventListener("change", sync);
    sync();
    form.appendChild(button("Pause", "pause", function () {
      var k = kind.input.value;
      var scope = { kind: k, provider: "", action: "", name: "" };
      if (k !== "global") {
        scope.provider = provider.input.value;
      }
      if (k === "action") {
        scope.action = action.input.value;
        scope.name = action.input.value === "tool" ? name.input.value : "";
      }
      write("/api/pause", { scope: scope, reason: reason.input.value });
    }));
    return form;
  }

  function select(text, options) {
    var label = el("label", "", text);
    var input = el("select");
    options.forEach(function (o) {
      var opt = el("option", "", o[1]);
      opt.value = o[0];
      input.appendChild(opt);
    });
    label.appendChild(input);
    return { label: label, input: input };
  }

  function textInput(text, max) {
    var label = el("label", "", text);
    var input = el("input");
    input.type = "text";
    input.maxLength = max;
    label.appendChild(input);
    return { label: label, input: input };
  }

  byId("pause").after(pauseForm());
  byId("refresh").addEventListener("click", load);
  start().then(function () {
    load();
    setInterval(load, REFRESH_MS);
  });
})();
