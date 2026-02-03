// Modal handling
function openModal(modalId, title) {
  const modal = document.getElementById(modalId);
  if (modal) {
    modal.classList.add('open');
    document.body.style.overflow = 'hidden';
    if (title) {
      const titleEl = document.getElementById('modal-title');
      if (titleEl) {
        titleEl.textContent = title;
      }
    }
  }
}

function closeModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) {
    modal.classList.remove('open');
    document.body.style.overflow = '';
  }
}

// Close modal when clicking backdrop
document.addEventListener('click', function(e) {
  if (e.target.classList.contains('modal-backdrop')) {
    e.target.classList.remove('open');
    document.body.style.overflow = '';
  }
});

// Close modal with Escape key
document.addEventListener('keydown', function(e) {
  if (e.key === 'Escape') {
    const openModals = document.querySelectorAll('.modal-backdrop.open');
    openModals.forEach(function(modal) {
      modal.classList.remove('open');
    });
    document.body.style.overflow = '';
  }
});

// Confirm delete
function confirmDelete(message, url) {
  if (confirm(message || 'Are you sure you want to delete this?')) {
    htmx.ajax('DELETE', url, {
      target: 'body',
      swap: 'none'
    }).then(function() {
      // Reload the page after successful delete
      window.location.reload();
    });
  }
}

// JSON syntax highlighting
function highlightJSON(json) {
  if (typeof json !== 'string') {
    json = JSON.stringify(json, null, 2);
  }
  return json.replace(
    /("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g,
    function(match) {
      let cls = 'json-number';
      if (/^"/.test(match)) {
        if (/:$/.test(match)) {
          cls = 'json-key';
        } else {
          cls = 'json-string';
        }
      } else if (/true|false/.test(match)) {
        cls = 'json-boolean';
      } else if (/null/.test(match)) {
        cls = 'json-null';
      }
      return '<span class="' + cls + '">' + match + '</span>';
    }
  );
}

// Apply JSON highlighting on load
document.addEventListener('DOMContentLoaded', function() {
  document.querySelectorAll('.json-highlight').forEach(function(el) {
    try {
      const json = JSON.parse(el.textContent);
      el.innerHTML = highlightJSON(JSON.stringify(json, null, 2));
    } catch (e) {
      // Not valid JSON, leave as is
    }
  });
});

// htmx events
document.body.addEventListener('htmx:afterSwap', function(evt) {
  // Re-apply JSON highlighting after htmx swaps
  evt.detail.target.querySelectorAll('.json-highlight').forEach(function(el) {
    try {
      const json = JSON.parse(el.textContent);
      el.innerHTML = highlightJSON(JSON.stringify(json, null, 2));
    } catch (e) {
      // Not valid JSON, leave as is
    }
  });
});

// Flash messages auto-hide
document.addEventListener('DOMContentLoaded', function() {
  const flashes = document.querySelectorAll('.flash');
  flashes.forEach(function(flash) {
    setTimeout(function() {
      flash.style.opacity = '0';
      flash.style.transition = 'opacity 0.3s';
      setTimeout(function() {
        flash.remove();
      }, 300);
    }, 5000);
  });
});

// Copy to clipboard
function copyToClipboard(text) {
  navigator.clipboard.writeText(text).then(function() {
    // Show brief feedback
    const btn = event.target;
    const originalText = btn.textContent;
    btn.textContent = 'Copied!';
    setTimeout(function() {
      btn.textContent = originalText;
    }, 1500);
  });
}

// Entity validation patterns (matching Tailscale's CheckTag rules)
const VALIDATION_PATTERNS = {
  tag: /^tag:[a-zA-Z][a-zA-Z0-9\-]*$/,
  group: /^group:[a-zA-Z][a-zA-Z0-9\-]*$/,
  svc: /^svc:[a-zA-Z][a-zA-Z0-9\-]*$/,
  ipset: /^ipset:[a-zA-Z][a-zA-Z0-9\-]*$/,
  host: /^[a-zA-Z][a-zA-Z0-9\-]*$/,
  email: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+$/,
  ip: /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/,
  autogroup: /^autogroup:(internet|self|owner|admin|member|tagged|auditor|billing-admin|it-admin|network-admin|nonroot|shared|danger-all)$/
};

// Real-time validation for form inputs
function setupFormValidation(container) {
  var root = container || document;
  var inputs = root.querySelectorAll('input[pattern]');

  console.log('[Validation] Found ' + inputs.length + ' inputs with pattern attribute');

  inputs.forEach(function(input) {
    // Skip if already setup
    if (input.dataset.validationSetup === 'true') {
      console.log('[Validation] Skipping already setup input:', input.name);
      return;
    }
    input.dataset.validationSetup = 'true';
    console.log('[Validation] Setting up validation for input:', input.name, 'pattern:', input.pattern);

    // Create error message element
    var errorEl = document.createElement('div');
    errorEl.className = 'field-error';
    errorEl.textContent = input.title || 'Invalid format';
    errorEl.style.display = 'none';
    input.parentElement.appendChild(errorEl);

    function validateInput() {
      input.classList.add('touched');
      var isValid = input.validity.valid;
      var hasValue = input.value.length > 0;

      if (hasValue && !isValid) {
        input.style.borderColor = '#dc3545';
        errorEl.style.display = 'block';
      } else if (hasValue && isValid) {
        input.style.borderColor = '#28a745';
        errorEl.style.display = 'none';
      } else {
        input.style.borderColor = '';
        errorEl.style.display = 'none';
      }
    }

    input.addEventListener('input', validateInput);
    input.addEventListener('blur', validateInput);
  });
}

// Listen for all htmx events that might add new content
document.body.addEventListener('htmx:afterSwap', function(evt) {
  console.log('[Validation] htmx:afterSwap event fired');
  // Small delay to ensure DOM is updated
  setTimeout(function() {
    setupFormValidation(document);
  }, 10);
});

document.body.addEventListener('htmx:load', function(evt) {
  console.log('[Validation] htmx:load event fired');
  setTimeout(function() {
    setupFormValidation(document);
  }, 10);
});

// Initial setup
document.addEventListener('DOMContentLoaded', function() {
  console.log('[Validation] DOMContentLoaded - initial setup');
  setupFormValidation(document);
});
