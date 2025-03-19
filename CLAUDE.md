# Protocol-Attacker Development Guide

## Build Commands
- Build project: `mvn clean install`
- Run all tests: `mvn test`
- Run single test: `mvn test -Dtest=FullyQualifiedTestName` (e.g., `mvn test -Dtest=de.rub.nds.protocol.crypto.key.KeyGeneratorTest`)
- Run integration tests: `mvn failsafe:integration-test`
- Format code: `mvn spotless:apply`
- Static analysis: `mvn spotbugs:check pmd:check`
- Generate Javadoc: `mvn javadoc:javadoc`

## Code Style
- Java version: JDK 21
- Formatting: Google Java Style (AOSP variant)
- Indentation: 4 spaces
- Imports: Ordered and unused imports removed
- Line endings: Git attributes with trailing whitespace trimmed
- License header: Required on all files (see license_header_plain.txt)
- Testing: JUnit 5 with optional IntegrationTest/SlowTest annotations
- Logging: Log4j2
- Error handling: Custom exceptions in exception package