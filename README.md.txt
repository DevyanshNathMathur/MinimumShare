# MinimumShare

**Context-Aware Privacy & Data Exposure Checker**

> Share only what the situation needs.

MinimumShare is a browser-based privacy tool that helps users review sensitive information before sharing text in different situations such as public posts, AI/chatbot conversations, customer support messages, job applications, or communication with unknown people.

Unlike simple pattern scanners, MinimumShare considers **where the information is being shared** before recommending whether an item is likely needed, should be reviewed, should be avoided, or should never be shared.

---

## Features

### Context-Aware Privacy Analysis

Users can select the intended sharing context:

- Public Post
- AI / Chatbot
- Unknown Person
- Customer Support
- Job Application

The same information can receive different recommendations depending on the selected context.

---

### Sensitive Data Detection

MinimumShare can identify common sensitive-data patterns including:

- Email addresses
- Phone numbers
- OTP / verification codes
- UPI IDs
- Payment-card-like numbers validated using the Luhn algorithm
- Password disclosures
- API keys and access tokens
- IPv4 addresses
- URLs
- Possible long identification numbers
- User-defined protected terms

---

### Privacy Exposure Score

The application calculates a deterministic exposure score from **0 to 100** based on:

- type of information detected
- recommendation severity
- selected sharing context
- repeated occurrences

The result is presented using exposure bands ranging from **Minimal** to **Critical**.

---

### Data Exposure Map

Detected information is grouped into privacy categories:

- Contact
- Authentication
- Financial
- Technical
- Identifiers
- Other

Each category receives an independent exposure value.

---

### Safe Review

The original text is displayed with detected information highlighted so users can understand exactly which portions may require attention.

---

### Minimum Necessary Version

MinimumShare automatically generates a sanitized version of the text.

Sensitive or unnecessary information is replaced with placeholders such as:

- `[EMAIL]`
- `[PHONE]`
- `[OTP REMOVED]`
- `[API KEY REMOVED]`
- `[PAYMENT DETAILS REMOVED]`
- `[PROTECTED TERM]`

Information considered appropriate for the selected context can remain unchanged.

---

### Privacy Receipt

After analysis, the application summarizes:

- total detected items
- items recommended for redaction
- items retained
- estimated exposure reduction

---

### Protected Terms

Users can define their own words or phrases that should never be shared.

These terms are processed locally and are automatically recommended for redaction.

---

## Privacy and Security

MinimumShare is designed as a client-side application.

- Text is processed locally in the browser
- No backend server is required
- No user text is uploaded
- No database is used
- No account is required
- No analytics are used
- No cookies are required
- No localStorage or sessionStorage is used

User-controlled text is rendered using safe DOM methods rather than being inserted as executable HTML.

---

## Technology

- HTML5
- CSS3
- Vanilla JavaScript
- IBM Bob for AI-assisted development

No external JavaScript framework, backend service, API, package manager, or database is required.

---

## Project Structure

```text
MinimumShare/
│
├── index.html
├── styles.css
├── rules.js
├── app.js
└── README.md

## Author

Developed by Devyansh Nath Mathur.

## Copyright

Copyright © 2026 Devyansh Nath Mathur. All rights reserved.