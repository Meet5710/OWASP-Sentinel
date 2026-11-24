/**
 * OWASP Sentinel - Non-Technical / Executive Explanations & Real-World Analogies
 *
 * Translates complex technical cybersecurity vulnerabilities into plain English,
 * relatable real-world analogies, and concrete business/reputation risks for non-IT
 * executives, clients, compliance officers, and management.
 */

export interface NonTechnicalExplanation {
  simpleTitle: string;
  whatItMeans: string;
  analogy: string;
  businessRisk: string;
  managementAction: string;
  urgency: 'Immediate Action Required' | 'High Priority' | 'Moderate Priority' | 'Good Practice';
}

const EXPLANATIONS_BY_RULE: Record<string, NonTechnicalExplanation> = {
  'RULE-SEC-001': {
    simpleTitle: 'Missing Web Browser Security Envelopes (Security Headers)',
    whatItMeans:
      'The website sends information to visitors without instructing their web browsers to turn on essential security shields (such as Strict-Transport-Security and X-Frame-Options).',
    analogy:
      'Imagine sending confidential business letters using postcards instead of sealed, tamper-evident security envelopes. Anyone handling the mail along the way can peek at or alter the contents.',
    businessRisk:
      'Attackers on shared networks (such as coffee shops or hotel Wi-Fi) could force visitors to downgrade to unencrypted connections, or embed your website inside a fake clone to trick users into giving away passwords.',
    managementAction:
      'Direct the web operations team to add modern defensive security headers (HSTS, CSP, and X-Frame-Options) to the web server configuration.',
    urgency: 'High Priority',
  },
  'RULE-SEC-002': {
    simpleTitle: 'Unencrypted Website Connection Available (Plain HTTP)',
    whatItMeans:
      'The website still allows visitors to connect using the old unencrypted "http://" protocol instead of strictly redirecting everyone to the secure "https://" padlock.',
    analogy:
      'Like speaking customer credit card numbers out loud in a crowded public restaurant instead of whispering them in a private soundproof booth.',
    businessRisk:
      'Exposes customer logins and browsing activity to eavesdropping on public Wi-Fi networks. Can trigger "Not Secure" warnings in Google Chrome and Safari, damaging company reputation.',
    managementAction:
      'Instruct your hosting provider to configure an automatic permanent redirect (HTTP 301) from HTTP to HTTPS for all pages.',
    urgency: 'Immediate Action Required',
  },
  'RULE-SEC-003': {
    simpleTitle: 'Unprotected User Login Badges (Cookie Security Flags)',
    whatItMeans:
      'When users log in, the digital pass (cookie) that remembers who they are is issued without digital locks like "Secure", "HttpOnly", and "SameSite".',
    analogy:
      'Giving visitors a physical office keycard without a photo or hologram, and allowing anyone standing near them to make an instant clone of the keycard.',
    businessRisk:
      'Malicious scripts or hackers on the same network could copy the login badge and impersonate logged-in users, accessing private accounts without knowing the user password.',
    managementAction:
      'Instruct developers to enforce "Secure; HttpOnly; SameSite=Lax" flags on all authentication and session cookies.',
    urgency: 'High Priority',
  },
  'RULE-SEC-004': {
    simpleTitle: 'Website Software Brand & Version Publicly Disclosed',
    whatItMeans:
      'The server openly announces the exact brand and version number of its background operating software to anyone who visits.',
    analogy:
      'Hanging a sign on the front door of your office announcing the exact make, model, and year of your burglar alarm system.',
    businessRisk:
      'Gives potential attackers an exact roadmap. They can search online vulnerability catalogs to find pre-made hacking tools that specifically target that exact version.',
    managementAction:
      'Tell the web server administrator to hide software version banners (e.g. ServerTokens Prod in Apache or server_tokens off in Nginx).',
    urgency: 'Moderate Priority',
  },
  'RULE-SEC-005': {
    simpleTitle: 'Permissive Cross-Website Data Sharing (CORS Misconfiguration)',
    whatItMeans:
      'The website tells web browsers that external, third-party websites are allowed to read private data directly from your server.',
    analogy:
      'An office receptionist who hands confidential internal company documents to courier drivers without verifying which company sent them.',
    businessRisk:
      'A visitor who has your website open in one tab while browsing another website could have their private data silently stolen by the other site.',
    managementAction:
      'Instruct engineers to restrict Cross-Origin Resource Sharing (CORS) strictly to trusted, verified company domain names.',
    urgency: 'High Priority',
  },
  'RULE-SEC-006': {
    simpleTitle: 'Internal Secret Files & Blueprints Left Publicly Accessible',
    whatItMeans:
      'Hidden files containing internal passwords, database connection strings, or version control history (such as .env or .git) can be downloaded by the public.',
    analogy:
      'Leaving building blueprints, master keys, and safe combination notes sitting on a table in the public reception lobby.',
    businessRisk:
      'Extreme danger of a full company data breach. Attackers can obtain administrative database passwords or cloud credentials directly from these files.',
    managementAction:
      'Immediately block web server access to all hidden dot-files and directories (e.g. .env, .git) and rotate any exposed passwords.',
    urgency: 'Immediate Action Required',
  },
  'RULE-SEC-007': {
    simpleTitle: 'Dangerous Communication Commands Permitted (HTTP Methods)',
    whatItMeans:
      'The web server accepts diagnostic or editing commands (like TRACE or open PUT/DELETE) that should normally be disabled for public visitors.',
    analogy:
      'A retail store allowing shoppers to access the manager’s inventory override console in the middle of the shopping aisles.',
    businessRisk:
      'Attackers can exploit the TRACE command to steal secret authentication credentials or bypass proxy security controls.',
    managementAction:
      'Disable TRACE, TRACK, and unnecessary write methods in the web server and load balancer settings.',
    urgency: 'Moderate Priority',
  },
  'RULE-SEC-008': {
    simpleTitle: 'Public Directory Browsing Enabled (Open Folder Catalog)',
    whatItMeans:
      'When a folder does not have a homepage, the server automatically displays a clickable list of all files stored inside that folder.',
    analogy:
      'Leaving the door to a private corporate filing room wide open, with a catalog of all confidential folders posted at the entrance.',
    businessRisk:
      'Visitors can locate and download unintended files, including old backups, draft documents, logs, and internal scripts.',
    managementAction:
      'Turn off directory indexing across all web server directories (Options -Indexes in Apache, autoindex off in Nginx).',
    urgency: 'Moderate Priority',
  },
  'RULE-SEC-009': {
    simpleTitle: 'Missing Clickjacking & Content Shielding (CSP Defect)',
    whatItMeans:
      'The website does not restrict which external scripts can load, and allows itself to be framed inside third-party websites.',
    analogy:
      'Placing an invisible transparent sheet over an ATM screen so that when a customer presses what looks like "Balance Inquiry", they are secretly clicking "Transfer Money".',
    businessRisk:
      'Malicious websites can trick your users into clicking invisible buttons or authorizing transactions under the impression they are on a trusted site.',
    managementAction:
      'Deploy an X-Frame-Options: DENY header and configure a strict Content-Security-Policy (CSP) header.',
    urgency: 'High Priority',
  },
  'RULE-SEC-010': {
    simpleTitle: 'Outdated Third-Party Software Component (Supply Chain Risk)',
    whatItMeans:
      'The application relies on an external software library or framework version that has known security flaws published on the internet.',
    analogy:
      'Installing a front door lock from 10 years ago where duplicate master keys are already widely circulating among burglars.',
    businessRisk:
      'Automated scanning bots constantly look for sites running these exact outdated versions to deploy automated exploits.',
    managementAction:
      'Have developers upgrade the identified third-party package to the latest supported stable release.',
    urgency: 'High Priority',
  },
  'RULE-SEC-011': {
    simpleTitle: 'Developer Test or Debug Console Left Active in Production',
    whatItMeans:
      'Diagnostic tools, database management consoles, or staging endpoints intended only for developers during testing were left active on the live website.',
    analogy:
      'Leaving the building contractor’s temporary scaffolding, master power switch, and bypass keys permanently attached to the finished building.',
    businessRisk:
      'Allows unauthorized users to view internal system errors, environment variables, or database schemas.',
    managementAction:
      'Remove or password-protect all debug and testing endpoints before deploying to production.',
    urgency: 'High Priority',
  },
  'RULE-SEC-012': {
    simpleTitle: 'Outdated Encryption Protocol Supported (Weak TLS)',
    whatItMeans:
      'The website accepts connections using older, obsolete encryption standards (such as TLS 1.0 or TLS 1.1) that modern security standards have retired.',
    analogy:
      'Locking a bank vault with a vintage padlock that modern security tools can bypass in a few minutes.',
    businessRisk:
      'Violates regulatory compliance frameworks (such as PCI-DSS for credit cards and ISO 27001), putting the company at risk of failed audits.',
    managementAction:
      'Disable TLS 1.0 and TLS 1.1 on your web server and load balancer, allowing only TLS 1.2 and TLS 1.3.',
    urgency: 'Moderate Priority',
  },
  'RULE-SEC-013': {
    simpleTitle: 'Administrative or Management Portal Missing Proper Protection',
    whatItMeans:
      'An internal administrative page or control panel can be accessed directly without an enforced login requirement or network restriction.',
    analogy:
      'An "Employees Only" executive office that lacks a lock or badge scanner, letting anyone off the street walk right in.',
    businessRisk:
      'Unauthorized individuals could view private operational data, modify system configurations, or tamper with customer accounts.',
    managementAction:
      'Require strong authentication, multi-factor verification (MFA), and IP address whitelisting for all administrative portals.',
    urgency: 'Immediate Action Required',
  },
  'RULE-SEC-014': {
    simpleTitle: 'Server Request Manipulation (SSRF Potential)',
    whatItMeans:
      'The website accepts a web address supplied by a user and instructs its own background servers to fetch that address without verifying its safety.',
    analogy:
      'Tricking an authorized company courier into picking up packages from a restricted private vault because the courier holds an all-access security pass.',
    businessRisk:
      'An attacker could trick your server into probing internal corporate databases or private cloud metadata services that are hidden from the public internet.',
    managementAction:
      'Implement strict destination URL whitelisting and block server requests to internal private IP addresses (e.g. 10.x.x.x, 192.168.x.x, 169.254.x.x).',
    urgency: 'Immediate Action Required',
  },
  'RULE-SEC-015': {
    simpleTitle: 'Unscreened File Upload Processing',
    whatItMeans:
      'The website allows visitors to upload files without thoroughly verifying their true file format, extension, and safety.',
    analogy:
      'Allowing packages into a corporate headquarters mailroom without inspecting them through a scanner or verifying the sender.',
    businessRisk:
      'An attacker could upload a malicious program or web shell that runs on your server, taking full control of the host machine.',
    managementAction:
      'Validate uploaded files by inspecting their binary signatures, store files on an isolated cloud storage bucket, and disable script execution.',
    urgency: 'Immediate Action Required',
  },
  'RULE-SEC-016': {
    simpleTitle: 'Unfiltered User Input Echo (Reflected Scripting / XSS)',
    whatItMeans:
      'When someone enters text into a search box or web address, the website immediately displays it back on the screen without cleaning up special characters.',
    analogy:
      'A building public address intercom that automatically repeats whatever anyone whispers into it, including dangerous fake instructions to all occupants.',
    businessRisk:
      'An attacker could send a malicious link to your customers that steals their login sessions or redirects them to a convincing fake login page.',
    managementAction:
      'Ensure all user-supplied text is properly HTML-encoded and sanitized before being displayed on web pages.',
    urgency: 'Immediate Action Required',
  },
  'RULE-SEC-017': {
    simpleTitle: 'Database Query Manipulation (SQL Injection Risk)',
    whatItMeans:
      'The website accepts input from visitors and uses it directly in database queries without keeping user input separate from database commands.',
    analogy:
      'Handing a bank teller a withdrawal slip written with confusing legal phrases that tricks the teller into emptying the entire vault into your bag.',
    businessRisk:
      'Critical risk: An attacker could read the entire database (customer records, passwords, financials) or delete tables entirely.',
    managementAction:
      'Enforce parameterized database queries (prepared statements) across all application database calls immediately.',
    urgency: 'Immediate Action Required',
  },
  'RULE-SEC-018': {
    simpleTitle: 'Personal Data or Sensitive Details Visible in Web Code',
    whatItMeans:
      'Customer email addresses, internal developer notes, or private identifiers are visible in the underlying webpage source code.',
    analogy:
      'Leaving customer contact lists and private internal memos sitting on top of the customer reception counter.',
    businessRisk:
      'Could lead to regulatory fines under data privacy laws (such as GDPR or CCPA) and exposes customer emails to automated spam harvesters.',
    managementAction:
      'Audit webpage templates to ensure private data and developer comments are removed before pages are sent to visitors.',
    urgency: 'Moderate Priority',
  },
  'RULE-SEC-019': {
    simpleTitle: 'Unsafe Document Parser (XML External Entity Risk)',
    whatItMeans:
      'The system parses XML documents with external reference loading enabled, allowing documents to reference files outside themselves.',
    analogy:
      'A company librarian who, when asked to read a book, automatically follows hidden notes inside the book that tell them to photocopy private personnel files from the back office.',
    businessRisk:
      'Attackers can submit crafted XML documents to trick the server into sending back private system configuration files or passwords.',
    managementAction:
      'Configure XML parsers to disable external DTDs (Document Type Definitions) and entity resolution entirely.',
    urgency: 'Immediate Action Required',
  },
};

/**
 * Returns a crystal-clear, non-technical plain English explanation,
 * relatable real-world analogy, and business impact for any finding.
 */
export function getNonTechnicalExplanation(
  ruleId?: string,
  title?: string,
  issueType?: string
): NonTechnicalExplanation {
  // 1. Direct rule match
  if (ruleId && EXPLANATIONS_BY_RULE[ruleId]) {
    return EXPLANATIONS_BY_RULE[ruleId];
  }

  // 2. Fallback heuristic based on title or issueType keywords
  const combined = `${title || ''} ${issueType || ''} ${ruleId || ''}`.toLowerCase();

  if (combined.includes('hsts') || combined.includes('header')) {
    return EXPLANATIONS_BY_RULE['RULE-SEC-001'];
  }
  if (combined.includes('cookie')) {
    return EXPLANATIONS_BY_RULE['RULE-SEC-003'];
  }
  if (combined.includes('server') || combined.includes('banner') || combined.includes('disclosure')) {
    return EXPLANATIONS_BY_RULE['RULE-SEC-004'];
  }
  if (combined.includes('cors') || combined.includes('origin')) {
    return EXPLANATIONS_BY_RULE['RULE-SEC-005'];
  }
  if (combined.includes('env') || combined.includes('git') || combined.includes('exposed file')) {
    return EXPLANATIONS_BY_RULE['RULE-SEC-006'];
  }
  if (combined.includes('method') || combined.includes('trace')) {
    return EXPLANATIONS_BY_RULE['RULE-SEC-007'];
  }
  if (combined.includes('directory') || combined.includes('listing')) {
    return EXPLANATIONS_BY_RULE['RULE-SEC-008'];
  }
  if (combined.includes('clickjack') || combined.includes('csp') || combined.includes('frame')) {
    return EXPLANATIONS_BY_RULE['RULE-SEC-009'];
  }
  if (combined.includes('component') || combined.includes('dependency') || combined.includes('library')) {
    return EXPLANATIONS_BY_RULE['RULE-SEC-010'];
  }
  if (combined.includes('debug') || combined.includes('endpoint') || combined.includes('admin')) {
    return EXPLANATIONS_BY_RULE['RULE-SEC-011'];
  }
  if (combined.includes('ssl') || combined.includes('tls') || combined.includes('cipher')) {
    return EXPLANATIONS_BY_RULE['RULE-SEC-012'];
  }
  if (combined.includes('ssrf') || combined.includes('proxy')) {
    return EXPLANATIONS_BY_RULE['RULE-SEC-014'];
  }
  if (combined.includes('upload') || combined.includes('file')) {
    return EXPLANATIONS_BY_RULE['RULE-SEC-015'];
  }
  if (combined.includes('xss') || combined.includes('scripting')) {
    return EXPLANATIONS_BY_RULE['RULE-SEC-016'];
  }
  if (combined.includes('sql') || combined.includes('injection')) {
    return EXPLANATIONS_BY_RULE['RULE-SEC-017'];
  }
  if (combined.includes('sensitive') || combined.includes('pii') || combined.includes('email')) {
    return EXPLANATIONS_BY_RULE['RULE-SEC-018'];
  }
  if (combined.includes('xml') || combined.includes('xxe')) {
    return EXPLANATIONS_BY_RULE['RULE-SEC-019'];
  }

  // 3. Sensible generic fallback
  return {
    simpleTitle: title || 'Security Configuration Defect',
    whatItMeans:
      'The website or server is missing an established protective measure, which could allow unauthorized behavior under specific conditions.',
    analogy:
      'Like leaving a side window slightly unlatched on a commercial property: it doesn’t immediately cause an incident, but it lowers the barrier for an intruder.',
    businessRisk:
      'Weakens defense-in-depth security posture, increasing the risk of data exposure or security compliance issues.',
    managementAction:
      'Review the recommended technical remediation with your IT or development team and schedule a fix in your next maintenance cycle.',
    urgency: 'Moderate Priority',
  };
}

