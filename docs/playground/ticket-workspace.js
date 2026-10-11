// Keep this in sync with demo/samples/support-ticket-fr.txt. The browser test
// checks both copies, then exercises each expected entity through real WASM.
const FICTIONAL_TICKET = `Ticket CASE-2042 — livraison affichée en double

Bonjour, je m'appelle Camille verneuil.
Mon email est camille.verneuil@example.invalid.
Adresse de livraison : 24 rue des Nuages 75016 ville-exemple.

Après une nouvelle tentative, deux livraisons apparaissent pour la même commande.
Le journal de test contient cette fausse autorisation :
Authorization: Basic ZGVidWc6ZXhhbXBsZS1wYXNzd29yZA==

Peux-tu proposer les prochaines vérifications sans inventer une cause ?
`;

async function loadEngine() {
  const module = await import('./pkg/anon_pii.js');
  await module.default();
  return module;
}

// The prepared output is held separately from the DOM. Copying never reads a
// rendered preview or a value that could contain a revealed original.
export function mountTicketWorkspace() {
  const get = id => document.getElementById(id);
  const source = get('ticket-source');
  const prepared = get('ticket-prepared');
  const reply = get('ticket-reply');
  const restored = get('ticket-restored');
  const prepareButton = get('prepare-ticket');
  const protectButton = get('protect-selection');
  const copyTicketButton = get('copy-ticket');
  const restoreButton = get('restore-reply');
  const copyReplyButton = get('copy-reply');
  const ticketCopyFeedback = get('copy-ticket-feedback');
  const replyCopyFeedback = get('copy-reply-feedback');
  const status = get('ticket-status');
  const engineStatus = get('engstats');

  let engineModule = null;
  let engine = null;
  let sourceSnapshot = null;
  let preparedText = null;
  let restoredText = null;
  let restoreOutcome = '';
  let revision = 0;
  let copyPending = false;

  function updateControls() {
    prepareButton.disabled = !engineModule || !source.value.trim();
    protectButton.disabled = !engine || !preparedText;
    copyTicketButton.disabled = preparedText === null;
    // Keep keyboard focus during a pending write; copy() enforces this lock.
    copyTicketButton.setAttribute('aria-disabled', String(copyPending || copyTicketButton.disabled));
    reply.disabled = !engine;
    restoreButton.disabled = !engine || !reply.value.trim();
    copyReplyButton.disabled = restoredText === null;
    copyReplyButton.setAttribute('aria-disabled', String(copyPending || copyReplyButton.disabled));
  }

  function clearPrepared() {
    revision += 1;
    if (engine) {
      // Discard the session even if a damaged WASM instance cannot be freed.
      try { engine.free(); } catch { /* No session may survive a reset. */ }
    }
    engine = null;
    sourceSnapshot = null;
    preparedText = null;
    restoredText = null;
    restoreOutcome = '';
    prepared.value = '';
    reply.value = '';
    restored.value = '';
    ticketCopyFeedback.textContent = '';
    replyCopyFeedback.textContent = '';
    updateControls();
  }

  function clearSession() {
    source.value = '';
    clearPrepared();
    status.textContent = 'Session cleared. Copies on your clipboard or in other apps are unchanged.';
  }

  // Clear browser-restored form values on startup as well as on navigation.
  // No ticket, reply, or mapping is written to browser storage.
  clearSession();
  status.textContent = 'Enter a ticket or load the fictional example to begin.';
  window.addEventListener('pagehide', clearSession);

  source.addEventListener('input', () => {
    const hadSession = engine !== null;
    clearPrepared();
    status.textContent = hadSession
      ? 'Ticket changed. Prepare it again; the previous session and reply were cleared.'
      : 'Prepare this ticket when it is ready. Review the result before sharing it.';
    if (!source.value.trim()) {
      status.textContent = 'Enter a ticket or load the fictional example to begin.';
    }
  });

  get('load-example').addEventListener('click', () => {
    clearPrepared();
    source.value = FICTIONAL_TICKET;
    updateControls();
    status.textContent = 'Fictional example loaded. Prepare it to start a new session.';
    source.focus();
    source.setSelectionRange(0, 0);
    source.scrollTop = 0;
  });

  get('clear-session').addEventListener('click', () => {
    clearSession();
    source.focus();
  });

  prepareButton.addEventListener('click', () => {
    clearPrepared();
    if (!engineModule || !source.value.trim()) return;
    try {
      engine = new engineModule.Engine();
      sourceSnapshot = source.value;
      const result = JSON.parse(engine.anonymize(sourceSnapshot));
      if (typeof result.output !== 'string') throw new Error('Invalid engine result');
      preparedText = result.output;
      prepared.value = preparedText;
      source.scrollTop = 0;
      const count = engine.mapping_len();
      status.textContent = count === 0
        ? 'No values were detected. Review every sensitive value before copying; detection can miss them.'
        : `Ticket prepared: ${count} unique ${count === 1 ? 'value' : 'values'} mapped locally. Review the tokenized text for missed sensitive values before copying.`;
      updateControls();
    } catch {
      clearPrepared();
      status.textContent = 'The ticket could not be prepared. No prepared text is available. Try a shorter ticket or reload the page.';
    }
  });

  function currentSession() {
    if (engine && source.value !== sourceSnapshot) {
      clearPrepared();
      status.textContent = 'Ticket changed. Prepare it again; the previous session and reply were cleared.';
    }
    return engine !== null;
  }

  protectButton.addEventListener('click', () => {
    if (!currentSession() || preparedText === null) return;
    // A selection belongs to the exact prepared output, never a modified DOM
    // value. Refuse stale coordinates rather than protecting a different value.
    if (prepared.value !== preparedText) {
      prepared.value = preparedText;
      prepared.setSelectionRange(0, 0);
      status.textContent = 'The displayed text changed. Make a new selection in the prepared ticket and try again.';
      return;
    }
    const start = prepared.selectionStart;
    const end = prepared.selectionEnd;
    // Textarea coordinates count UTF-16 code units; the engine uses UTF-8 bytes.
    // Encoding half a surrogate pair would silently change the selected value.
    const splitsSurrogate = offset => offset > 0 && offset < preparedText.length
      && /[\uD800-\uDBFF]/.test(preparedText[offset - 1])
      && /[\uDC00-\uDFFF]/.test(preparedText[offset]);
    if (start >= end || splitsSurrogate(start) || splitsSurrogate(end)) {
      status.textContent = 'Select a complete value in the prepared ticket, then choose Protect selected text. The selection must not split a character.';
      return;
    }
    try {
      const encoder = new TextEncoder();
      const result = JSON.parse(engine.protect_range(
        preparedText,
        encoder.encode(preparedText.slice(0, start)).length,
        encoder.encode(preparedText.slice(0, end)).length,
      ));
      if (typeof result.token !== 'string' || !/^\[MANUAL_[a-f0-9]{8}\]$/.test(result.token)
        || result.output !== preparedText.slice(0, start) + result.token + preparedText.slice(end)) {
        throw new Error('Invalid protection result');
      }
      revision += 1;
      preparedText = result.output;
      prepared.value = preparedText;
      reply.value = '';
      restoredText = null;
      restoreOutcome = '';
      restored.value = '';
      ticketCopyFeedback.textContent = '';
      replyCopyFeedback.textContent = '';
      updateControls();
      prepared.focus();
      prepared.setSelectionRange(start, start + result.token.length);
      status.textContent = 'Selected occurrence protected locally. Review other occurrences and remaining sensitive values before copying. Any previous reply was cleared.';
    } catch {
      status.textContent = 'The selection could not be protected. Select complete text outside existing tokens and try again.';
    }
  });

  reply.addEventListener('input', () => {
    revision += 1;
    restoredText = null;
    restoreOutcome = '';
    restored.value = '';
    replyCopyFeedback.textContent = '';
    updateControls();
    if (engine) status.textContent = 'Reply changed. Restore it to see the original values for this ticket.';
  });

  restoreButton.addEventListener('click', () => {
    if (!currentSession() || !reply.value.trim()) return;
    revision += 1;
    replyCopyFeedback.textContent = '';
    try {
      const result = JSON.parse(engine.restore_report(reply.value));
      if (typeof result.output !== 'string'
        || !Number.isSafeInteger(result.restored_count) || result.restored_count < 0
        || !Number.isSafeInteger(result.unresolved_count) || result.unresolved_count < 0) {
        throw new Error('Invalid restore result');
      }
      restoredText = result.output;
      const count = result.restored_count;
      const unresolved = result.unresolved_count;
      restoreOutcome = count > 0
        ? `Restored ${count} token ${count === 1 ? 'occurrence' : 'occurrences'} with the current ticket mapping. Original sensitive values are visible.`
        : 'No token occurrences were restored.';
      restoreOutcome += unresolved > 0
        ? ` ${unresolved} unrecognized token-shaped ${unresolved === 1 ? 'placeholder' : 'placeholders'} left unchanged. Check that the reply uses this ticket’s unchanged tokens.`
        : ' Review the reply; changed or incomplete tokens may not be recognized.';
      restored.value = restoredText;
      reply.scrollTop = 0;
      updateControls();
      status.textContent = restoreOutcome;
    } catch {
      restoredText = null;
      restoreOutcome = '';
      restored.value = '';
      updateControls();
      status.textContent = 'The reply could not be restored. Check the reply and try again, or prepare a fresh ticket.';
    }
  });

  async function copy(text, field, feedback, successMessage, outcome = '') {
    if (text === null || copyPending) return;
    // A pending clipboard write cannot be cancelled. Keep this shared lock even
    // when the session changes, so an older write cannot finish after a new one.
    copyPending = true;
    const copyRevision = revision;
    feedback.textContent = 'Copying…';
    status.textContent = 'Copying to clipboard…';
    updateControls();
    try {
      await navigator.clipboard.writeText(text);
      if (copyRevision === revision) {
        feedback.textContent = 'Copied';
        status.textContent = successMessage;
      }
    } catch {
      if (copyRevision !== revision) return;
      field.value = text;
      field.focus();
      field.select();
      feedback.textContent = 'Text selected for manual copy';
      status.textContent = 'Clipboard access was unavailable. The text is selected; use your browser’s Copy command or Ctrl+C / ⌘C.' + (outcome ? ` ${outcome}` : '');
    } finally {
      copyPending = false;
      if (copyRevision !== revision) feedback.textContent = '';
      updateControls();
    }
  }

  copyTicketButton.addEventListener('click', () => {
    if (!currentSession()) return;
    void copy(preparedText, prepared, ticketCopyFeedback, 'Tokenized ticket copied. Review it before sharing with your chosen AI tool; keep the tokens intact.');
  });
  copyReplyButton.addEventListener('click', () => {
    if (!currentSession()) return;
    void copy(restoredText, restored, replyCopyFeedback, `Reply copied. ${restoreOutcome}`, restoreOutcome);
  });

  loadEngine().then(module => {
    engineModule = module;
    engineStatus.textContent = `Local engine ready · ${module.entity_type_count()} entity types · ${module.pattern_count()} patterns · heuristic name detection enabled`;
    updateControls();
  }).catch(() => {
    clearPrepared();
    engineStatus.textContent = 'The local engine failed to load. Reload this page to try again. JavaScript and WebAssembly are required.';
    status.textContent = 'Engine unavailable. Your ticket has not been prepared; the CLI below is another way to use anon-pii.';
  });
}
