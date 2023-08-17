podTemplate(yaml: '''
    apiVersion: v1
    kind: Pod
    spec:
      containers:
      - name: kubectl
        image: lachlanevenson/k8s-kubectl
        command:
        - sleep
        args:
        - 99d
      - name: go
        image: openjdk:11-jre-slim
        command:
        - sleep
        args:
        - 99d
      - name: kaniko
        image: gcr.io/kaniko-project/executor:debug
        command:
        - sleep
        args:
        - 9999999
        volumeMounts:
        - name: kaniko-secret
          mountPath: /kaniko/.docker
      restartPolicy: Never
      volumes:
      - name: kaniko-secret
        secret:
            secretName: dockercred
            items:
            - key: .dockerconfigjson
              path: config.json
''') {
  node(POD_LABEL) {
    stage('Get the project') {
        git url: 'https://github.com/Hardcorelevelingwarrior/chap3', branch: 'main'
    }
    container("go") {
        stage("Perform SAST with Sonarqube") {
            def scannerHome = tool name: 'sonarqube', type: 'hudson.plugins.sonar.SonarRunnerInstallation'
            def jdkHome = tool name: 'Java 17', type: 'hudson.model.JDK'
            withSonarQubeEnv('sonarqube') {
                withEnv(["JAVA_HOME=${jdkHome}", "PATH+JDK=${jdkHome}/bin"]) {
                    sh "${scannerHome}/bin/sonar-scanner"
                }
            }
        }
    }
    container("kaniko") {
        stage("Dockerizing the app") {
            sh '''
                /kaniko/executor --context `pwd` --destination conmeobeou1253/go-app:1.0
            '''
        }
    }
    stage('Deploy to Kubernetes') {
         container('kubectl') {
            script {
                // Define the Kubernetes deployment
                def deployment = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  replicas: 1
  selector:
    matchLabels:
      app: my-app
  template:
    metadata:
      labels:
        app: my-app
    spec:
      containers:
      - name: my-app
        image: conmeobeou1253/go-app:1.0
        ports:
        - containerPort: 8080
"""

                // Apply the Kubernetes deployment
                sh "echo '${deployment}' | kubectl apply -f -"
            }
    }
    }

stage('ZAP Scan') {
        // Define the ZAP ScanType
        container('kubectl') {
        def zapScan = """
# SPDX-FileCopyrightText: the secureCodeBox authors
#
# SPDX-License-Identifier: Apache-2.0

apiVersion: "execution.securecodebox.io/v1"
kind: Scan
metadata:
  name: "zap-baseline-scan-bodgeit"
  labels:
    organization: "OWASP"
spec:
  scanType: "zap-baseline-scan"
  parameters:
    # target URL including the protocol
    - "-t"
    - "http://10.244.0.36:8080"
    # show debug messages
    - "-d"
    # the number of minutes to spider for (default 1)
    - "-m"
    - "2"

"""

        // Apply the ZAP ScanType
        sh "echo '${zapScan}' | kubectl apply -f -"

        // Wait for the ZAP scan to complete
sh '''while true; do
    state=$(kubectl get scans.execution.securecodebox.io zap-baseline-scan-bodgeit -o jsonpath="{.status.state}")
    if [ "$state" == "Done" ]; then
        break
    fi
    sleep 1
done
'''
sh 'kubectl describe scan zap-baseline-scan-bodgeit' 
// Get the download links for the scan results
                def findingDownloadLink = sh(returnStdout: true, script: 'kubectl get scans.execution.securecodebox.io zap-baseline-scan-bodgeit -o jsonpath="{.status.findingDownloadLink}"').trim()
                def rawResultDownloadLink = sh(returnStdout: true, script: 'kubectl get scans.execution.securecodebox.io zap-baseline-scan-bodgeit -o jsonpath="{.status.rawResultDownloadLink}"').trim()

                // Download the scan results
                sh "curl -L -o findings.json '${findingDownloadLink}'"
                sh "curl -L -o zap-results.xml '${rawResultDownloadLink}'"

                // Archive the scan results as artifacts
                archiveArtifacts artifacts: 'findings.json,zap-results.xml', fingerprint: true
   }

}


}

}