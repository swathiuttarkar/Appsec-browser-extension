
// === SECURITY RULES ===
const rules = [
  {
    id: "INSECURE_PROTOCOL",
    description: "Form uses insecure (HTTP) action URL.",
    owasp: "A5:2021 - Security Misconfiguration",
    check: (doc) => {
      return [...doc.querySelectorAll("form")].filter(form =>
        form.action && form.action.startsWith("http://")
      );
    }
  },
  {
    id: "PASSWORD_MASKED",
    description: "Sensitive input field is not masked",
    owasp: "A2:2021 - Cryptographic Failures",
    check: (doc) => {
      return [...doc.querySelectorAll('input[type="text"]')].filter(input =>
        /password|token|otp/i.test(input.name)
      );
    }
  },
  {
    id: "INSECURE_FORM_ACTION",
    description: "Form action uses HTTP.",
    owasp: "A5:2021 - Security Misconfiguration",
    check: (doc) =>
      [...doc.querySelectorAll("form")].filter(f => f.action.startsWith("http://"))
  },
  {
    id: "PASSWORD_FIELD_NOT_SECURE",
    description: "Password field is not of type 'password'.",
    owasp: "A2:2021 - Cryptographic Failures",
    check: (doc) =>
      [...doc.querySelectorAll("input[name*=pass]")].filter(i => i.type !== "password")
  },
  {
    id: "AUTOCOMPLETE_ENABLED",
    description: "Sensitive fields should have autocomplete off.",
    owasp: "A3:2021 - Injection",
    check: (doc) =>
      [...doc.querySelectorAll("input[type=password], input[type=email]")].filter(i =>
        i.autocomplete !== "off"
      )
  },
  {
    id: "INLINE_EVENT_HANDLER",
    description: "Avoid inline JS event handlers.",
    owasp: "A6:2021 - Vulnerable & Outdated Components",
    check: (doc) =>
      [...doc.querySelectorAll("[onclick],[onmouseover],[onload]")].filter(Boolean)
  },


  {
    id: "XSS-INLINE-SCRIPT",
    description: "Inline JavaScript detected. This may expose the app to XSS.",
    owasp: "A03:2021 - Injection",
    check: (doc) => Array.from(doc.querySelectorAll("script:not([src])"))
  },
  {
    id: "INSECURE-JAVASCRIPT-URL",
    description: "Anchor/link uses a 'javascript:' URL — potential XSS vector.",
    owasp: "A03:2021 - Injection",
    check: (doc) => Array.from(doc.querySelectorAll("a[href^='javascript:']"))
  },
  {
    id: "EXTERNAL-LINK-WITHOUT-REL",
    description: "External link opens in new tab without rel='noopener' — may lead to tab hijacking.",
    owasp: "A01:2021 - Broken Access Control",
    check: (doc) => Array.from(doc.querySelectorAll("a[target='_blank']")).filter(a =>
      !a.hasAttribute("rel") || !a.getAttribute("rel").includes("noopener")
    )
  },
  {
    id: "MIXED-CONTENT-DETECTED",
    description: "Page is HTTPS but includes HTTP content — browser may block it.",
    owasp: "A06:2021 - Vulnerable and Outdated Components",
    check: (doc) => Array.from(doc.querySelectorAll("script[src], img[src], link[href]")).filter(el => {
      const src = el.getAttribute("src") || el.getAttribute("href");
      return location.protocol === "https:" && src && src.startsWith("http://");
    })
  },
  {
    id: "PORT-EXPOSURE",
    description: "Resource uses a non-standard port — may expose development or internal services.",
    owasp: "A09:2021 - Security Logging and Monitoring Failures",
    check: (doc) => Array.from(doc.querySelectorAll("script[src], link[href], img[src]")).filter(el => {
      const url = el.getAttribute("src") || el.getAttribute("href");
      return url && /:\d{2,5}/.test(url) && !url.startsWith("https://");
    })
  }

];

/*
  {
    id: "insecure_protocol",
    description: "Page is served over HTTP",
    owasp: "A1:2021 - Broken Access Control",
    check: () => {
      return location.protocol !== "https:" ? [location.href] : [];
    }
  },
*/