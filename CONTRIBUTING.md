# Contributing to NetSentinel

Thank you for your interest in contributing to **NetSentinel**! We welcome contributions from the community to help improve the project’s functionality, usability, and security.

This document outlines guidelines and best practices to help you make contributions that are consistent with the project goals and maintain high-quality standards.

---

## How to Contribute

### 1. Reporting Issues

If you find a bug or have a feature request, please check the [GitHub Issues](https://github.com/kaotickj/NetSentinel/issues) page to see if it has already been reported.

- If it exists, add relevant information or your use case to help us understand it better.
- If it does not exist, please open a new issue with a clear and descriptive title, detailed description, and steps to reproduce (if applicable).

### 2. Discussing Changes

For larger features or breaking changes, please open a discussion or an issue before starting work. This helps to coordinate efforts and ensure alignment with the project vision.

### 3. Making Code Contributions

#### Fork & Clone

- Fork the repository.
- Clone your fork locally:

```
git clone https://github.com/your-username/NetSentinel.git
cd NetSentinel
````

#### Create a Branch

* Create a feature branch for your work, using a descriptive name:

```
git checkout -b feature/your-feature-name
```

#### Development

* Write clear, concise, and well-documented code.
* Follow existing code style and conventions.
* Include comments where necessary, especially for complex logic.
* Add or update unit tests where appropriate.
* Ensure your code works on Python 3.7+.

#### Testing

* Run existing tests to ensure no regressions.
* Add tests for any new functionality.
* Test your changes thoroughly, especially for security-sensitive features.

#### Commit Messages

* Use clear, imperative-style commit messages.
* Reference related issue numbers when applicable.
* Example:

```
Fix bug in CIDR scanning logic to correctly iterate over IPs
```

#### Push & Pull Request

* Push your branch to your fork:

```
git push origin feature/your-feature-name
```

* Open a Pull Request (PR) against the main repository’s `main` branch.
* Fill the PR template with description, motivation, and related issues.
* Be responsive to feedback and requests for changes.

---

## Code of Conduct

This project adheres to a strict code of conduct. Please be respectful and constructive in all interactions.

---

## Development Environment

* Python 3.7 or higher is required.
* Install dependencies using:

```
pip install -r requirements.txt
```

* The project uses:

  * `scapy` for network scanning,
  * `impacket` and `smbprotocol` for SMB and Kerberos functionality,
  * `ldap3` for LDAP integration,
  * `pyfiglet` for CLI banner styling.

---

## Style Guidelines

* Follow [PEP 8](https://peps.python.org/pep-0008/) for Python code.
* Use consistent indentation (4 spaces).
* Limit lines to 79 characters.
* Use descriptive variable and function names.

---

## Additional Notes

* All code must be your original work or properly licensed for inclusion.
* Avoid committing sensitive data (passwords, keys).
* Ensure backward compatibility unless explicitly addressing breaking changes.
* Keep security best practices in mind, especially for authentication and scanning features.

---

Thank you for helping make **NetSentinel** a better tool for red teams and security professionals!

For any questions or guidance, feel free to open an issue or contact the maintainer.

---

**Maintainer:** Kaotick Jay
**Email:** [kaotickj@gmail.com](mailto:kaotickj@gmail.com)
**GitHub:** [github.com/kaotickj](https://github.com/kaotickj)

