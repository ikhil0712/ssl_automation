// Jenkinsfile — SSL Automation Pipeline
// Triggers a full SSL/TLS validation run and archives the HTML report.

pipeline {
    agent any

    // ── Parameters ──────────────────────────────────────────────────────────
    parameters {
        choice(
            name: 'REPORT_FORMAT',
            choices: ['html', 'json', 'text'],
            description: 'Output format for the validation report'
        )
        string(
            name: 'TAG_FILTER',
            defaultValue: '',
            description: 'Only validate targets with this tag (leave blank for all)'
        )
        booleanParam(
            name: 'FAIL_FAST',
            defaultValue: true,
            description: 'Fail the build if any target has a FAIL status'
        )
    }

    // ── Triggers: run daily at 06:00 UTC ────────────────────────────────────
    triggers {
        cron('0 6 * * *')
    }

    // ── Environment ──────────────────────────────────────────────────────────
    environment {
        REPORT_DIR    = "reports"
        PYTHONPATH    = "${WORKSPACE}/scripts"
        VENV_DIR      = "${WORKSPACE}/.venv"
    }

    stages {

        // ────────────────────────────────────────────────────────────────────
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        // ────────────────────────────────────────────────────────────────────
        stage('Setup Python') {
            steps {
                sh '''
                    python3 -m venv ${VENV_DIR}
                    . ${VENV_DIR}/bin/activate
                    pip install --quiet --upgrade pip
                    pip install --quiet -r requirements.txt
                '''
            }
        }

        // ────────────────────────────────────────────────────────────────────
        stage('Validate SSL / TLS') {
            steps {
                script {
                    def tagArg    = params.TAG_FILTER ? "--tag ${params.TAG_FILTER}" : ""
                    def failArg   = params.FAIL_FAST  ? "--fail-fast" : ""
                    def formatArg = "--format ${params.REPORT_FORMAT}"

                    sh """
                        . ${VENV_DIR}/bin/activate
                        mkdir -p ${REPORT_DIR} logs
                        python3 scripts/ssl_validator.py \\
                            --targets config/targets.yaml \\
                            --policy  config/policy.yaml  \\
                            ${formatArg}                   \\
                            ${tagArg}                      \\
                            ${failArg}
                    """
                }
            }
        }

        // ────────────────────────────────────────────────────────────────────
        stage('Archive Report') {
            steps {
                archiveArtifacts artifacts: 'reports/**', fingerprint: true
                archiveArtifacts artifacts: 'logs/**',    fingerprint: false
            }
        }

        // ────────────────────────────────────────────────────────────────────
        stage('Publish HTML Report') {
            when {
                expression { params.REPORT_FORMAT == 'html' }
            }
            steps {
                publishHTML([
                    allowMissing:          false,
                    alwaysLinkToLastBuild: true,
                    keepAll:               true,
                    reportDir:             'reports',
                    reportFiles:           '*.html',
                    reportName:            'SSL Validation Report',
                    reportTitles:          ''
                ])
            }
        }
    }

    // ── Post ─────────────────────────────────────────────────────────────────
    post {
        failure {
            echo '❌ SSL validation detected failures — review the archived report.'
            // Uncomment to send email notifications:
            // emailext(
            //     subject: "SSL Validation FAILED — ${env.JOB_NAME} #${env.BUILD_NUMBER}",
            //     body:     "View report: ${env.BUILD_URL}artifact/reports/",
            //     to:       'ops-team@example.com'
            // )
        }
        success {
            echo '✅ SSL validation passed.'
        }
        always {
            cleanWs(cleanWhenAborted: true, cleanWhenFailure: false, cleanWhenSuccess: false)
        }
    }
}
