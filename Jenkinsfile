pipeline {
    agent any

    environment {
        DOCKER_IMAGE = "yourusername/vuln-scanner"
        DOCKER_TAG   = "latest"
        KUBECONFIG   = credentials('kubeconfig')
        TARGET       = "http://testphp.vulnweb.com"   // Target to scan
    }

    stages {

        stage('Clone') {
            steps {
                echo '=== Stage 1: Cloning repository ==='
                checkout scm
            }
        }

        stage('Build') {
            steps {
                echo '=== Stage 2: Building Docker image ==='
                sh 'docker build -t ${DOCKER_IMAGE}:${DOCKER_TAG} .'
            }
        }

        stage('Test') {
            steps {
                echo '=== Stage 3: Running unit tests ==='
                sh '''
                    docker run --rm ${DOCKER_IMAGE}:${DOCKER_TAG} \
                    python -m pytest tests/ -v --tb=short
                '''
            }
        }

        stage('Push') {
            steps {
                echo '=== Stage 4: Pushing to DockerHub ==='
                withCredentials([usernamePassword(
                    credentialsId: 'dockerhub-creds',
                    usernameVariable: 'DOCKER_USER',
                    passwordVariable: 'DOCKER_PASS'
                )]) {
                    sh 'echo $DOCKER_PASS | docker login -u $DOCKER_USER --password-stdin'
                    sh 'docker push ${DOCKER_IMAGE}:${DOCKER_TAG}'
                }
            }
        }

        // 🔥 NEW DEVSECOPS STAGE
        stage('Security Quality Gate') {
            steps {
                echo '=== Stage 5: Running Security Scan ==='
                script {
                    // Call your scanner API (make sure app is running!)
                    def response = sh(
                        script: "curl -s http://localhost:5000/?url=${TARGET}",
                        returnStdout: true
                    ).trim()

                    echo "Scan Response: ${response}"

                    // Simple logic: fail if vulnerabilities found
                    if (response.contains("SQL Injection") || response.contains("XSS")) {
                        error("❌ Pipeline Aborted: High-Risk Vulnerabilities Found!")
                    } else {
                        echo "✅ Security Quality Gate Passed"
                    }
                }
            }
        }

        stage('Deploy') {
            steps {
                echo '=== Stage 6: Deploying to Kubernetes ==='
                sh '''
                    kubectl --kubeconfig=$KUBECONFIG apply -f k8s/deployment.yaml
                    kubectl --kubeconfig=$KUBECONFIG apply -f k8s/service.yaml
                    kubectl --kubeconfig=$KUBECONFIG rollout status deployment/vuln-scanner
                '''
            }
        }

    }

    post {
        success {
            echo '🎉 Pipeline completed successfully!'
        }
        failure {
            echo '❌ Pipeline FAILED. Check logs.'
        }
    }
}