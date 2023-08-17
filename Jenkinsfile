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
apiVersion: "execution.securecodebox.io/v1"
kind: Scan
metadata:
  name: "zap-scan"
spec:
  scanType: "zap"
  parameters:
    - "-t"
    - "http://10.244.0.36:8080"
"""

        // Apply the ZAP ScanType
        sh "echo '${zapScan}' | kubectl apply -f -"

        // Wait for the ZAP scan to complete
        sh 'kubectl wait --for=condition=ready pod -l app.kubernetes.io/instance=zap-scan --timeout=-1s'
    }
}

}

}