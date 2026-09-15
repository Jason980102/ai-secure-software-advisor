# AI Secure Software Advisor

An AI-powered software dependency and security analysis platform that identifies known vulnerabilities, evaluates dependency risks, and recommends safer software versions with developer-friendly explanations.

## Overview

AI Secure Software Advisor helps developers analyze project dependencies before deployment. The platform scans dependency versions against known vulnerability data, identifies security risks, recommends safer versions, and uses AI to explain findings and remediation steps.

The initial MVP focuses on Python projects using `requirements.txt`.

## MVP Features

- Parse and analyze Python `requirements.txt` dependencies
- Detect known vulnerabilities using the OSV vulnerability database
- Identify affected dependency versions
- Recommend safer or fixed package versions
- Calculate a security risk score based on detected vulnerabilities
- Generate AI-powered explanations and remediation guidance
- Store scan history and findings for later review
- Provide a web dashboard for viewing security reports

## Planned Architecture

```text
Next.js Frontend
       |
       | REST API
       v
FastAPI Backend
       |
       +---- Dependency Parser
       |
       +---- Vulnerability Scanner ---- OSV API
       |
       +---- Risk Scoring Engine
       |
       +---- Recommendation Engine
       |
       +---- AI Advisor ------------ LLM API
       |
       v
PostgreSQL
```

## Tech Stack

**Frontend**
- Next.js
- TypeScript

**Backend**
- FastAPI
- Python
- Pydantic
- SQLAlchemy

**Database**
- PostgreSQL

**Security Intelligence**
- OSV API

**AI**
- LLM API for security explanations and remediation guidance

**DevOps**
- Docker
- GitHub Actions
- Automated testing and CI/CD

## MVP Workflow

```text
requirements.txt
       ↓
Dependency Parsing
       ↓
Vulnerability Analysis
       ↓
Risk Assessment
       ↓
Version Recommendation
       ↓
AI Explanation
       ↓
Security Report
```

## Project Status

🚧 **Under active development**

Current milestone:

**v0.1 — Python Dependency Security Scanner**

The first version focuses on building the core dependency parsing and vulnerability analysis pipeline before expanding to additional package ecosystems.

## Roadmap

- [ ] Build FastAPI backend foundation
- [ ] Implement `requirements.txt` parser
- [ ] Integrate OSV vulnerability scanning
- [ ] Implement risk scoring
- [ ] Implement secure version recommendations
- [ ] Add PostgreSQL persistence
- [ ] Build Next.js security dashboard
- [ ] Add AI-generated security explanations
- [ ] Add automated tests
- [ ] Containerize services with Docker
- [ ] Configure GitHub Actions CI/CD
- [ ] Deploy public demo

### Future

- npm / `package.json` support
- GitHub repository scanning
- Additional vulnerability intelligence sources
- SBOM analysis
- Docker image analysis
- Automated pull request recommendations

## Disclaimer

This project provides software security recommendations based on publicly available vulnerability data. It is intended as a developer assistance tool and should not be treated as a replacement for professional security auditing.
