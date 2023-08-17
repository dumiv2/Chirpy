podTemplate(yaml: '''
    apiVersion: v1
    kind: Pod
    spec:
      containers:
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
container("go"){
    stage("Perform SAST with Sonarqube") {
      def scannerHome = tool name: 'sonarqube', type: 'hudson.plugins.sonar.SonarRunnerInstallation'
      def jdkHome = tool name: 'Java 17', type: 'hudson.model.JDK'
      withSonarQubeEnv('sonarqube') {
        withEnv(["JAVA_HOME=${jdkHome}", "PATH+JDK=${jdkHome}/bin"]) {
          sh "${scannerHome}/bin/sonar-scanner"
        }
      }
    }}
container("kaniko"){
    stage("Dockerizing the app"){
        sh 'ls -l /home/jenkins/agent/workspace/Gotest/go.mod'

                  sh '''
            /kaniko/executor --context `pwd` --destination conmeobeou1253/go-app:1.0
          '''
  }
}
}
}
