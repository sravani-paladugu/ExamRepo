pipeline {
    agent any
    environment {
        GITHUB_CREDENTIALS_ID = '9ed2ca16-c5b8-4d04-aaaa-8428591f50b3'
        TRIVY_SEVERITY = 'HIGH,MEDIUM'
        DOCKER_IMAGE = 'yq:latest' // Adjust the Docker image name as needed
        HIGH_SEVERITY_FLAG_FILE = 'high_severity_found.flag'
    }
    stages {
        stage('Checkout') {
            steps {
                checkout([$class: 'GitSCM', branches: [[name: 'main']],
                          userRemoteConfigs: [[credentialsId: GITHUB_CREDENTIALS_ID,
                                               url: 'https://github.com/sravani-paladugu/Exam-Repo.git']]]) // Adjust the URL as necessary
            }
        }
        stage('Build Docker Image') {
            steps {
                script {
                     bat "docker build -t ${env.DOCKER_IMAGE} ."
                }
            }
        }
        stage('Trivy Scan') {
            steps {
                script {
                      String outputPath = "${WORKSPACE}\\trivy-report.json"
                      bat "C:\\Users\\spaladug\\go\\bin\\trivy.exe image --severity ${TRIVY_SEVERITY} --format json --output ${outputPath} ${env.DOCKER_IMAGE}"
                }
            }
        }

        stage('Check for High Severity Alerts') {
            steps {
                script {
                    def filePath = "${WORKSPACE}\\trivy-report.json"
                    echo "Reading file from: ${filePath}"

                    if (!fileExists(filePath)) {
                        error("File does not exist: ${filePath}")
                    }

                    def reportJson = readFile(filePath).trim()

                    if (reportJson.isEmpty()) {
                        error("File is empty: ${filePath}")
                    }

                    boolean highSeverityFound = checkForHighSeverity(reportJson)

                    if (highSeverityFound) {
                        writeFile file: "${env.HIGH_SEVERITY_FLAG_FILE}", text: 'true'
                    }
                }
            }
        }

        stage('Send Alerts') {
            steps {
                script {
                    def highSeverityFoundFlag = 'false'
                    if (fileExists(env.HIGH_SEVERITY_FLAG_FILE)) {
                        highSeverityFoundFlag = readFile(env.HIGH_SEVERITY_FLAG_FILE).trim()
                    }

                    if (highSeverityFoundFlag == 'true') {
                        echo "High severity vulnerabilities detected, sending alerts..."
                        emailext(
                    subject: "ALERT: High Severity Vulnerabilities Detected!",
                    body: """<p>High severity vulnerabilities have been detected in the Docker image scan.</p>
                             <p>Please review the Jenkins build logs for details.</p>""",
                    mimeType: 'text/html',
                    to: 'sravanivrsec@example.com' // Replace with actual recipient email address
                )
                    } else {
                        echo "No high severity vulnerabilities detected, no alerts sent."
                    }
                }
            }
        }
    }
post {
        always {
            // Cleanup step for Windows
            script {
                if (isUnix()) {
                sh 'rm -f trivy-report.json'
            } else {
                bat 'del /f trivy-report.json'
            }
            echo "Cleaned up trivy-report.json"
            }
        }
    }
}


@NonCPS
boolean checkForHighSeverity(String jsonText) {
    def jsonSlurper = new groovy.json.JsonSlurper()
    def rootObject = jsonSlurper.parseText(jsonText)
    boolean highSeverityFound = false

    if (!rootObject.Results) {
        return false
    }

    rootObject.Results.each { result ->
        if (result.Vulnerabilities) {
            result.Vulnerabilities.each { vulnerability ->
                if (vulnerability.Severity == 'HIGH') {
                    echo "High severity vulnerability found: CVE-${vulnerability.VulnerabilityID} - ${vulnerability.Title}"
                    highSeverityFound = true
                }
            }
        }
    }
    return highSeverityFound
}
