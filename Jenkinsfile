podTemplate(yaml: '''
    apiVersion: v1
    kind: Pod
    spec:
      containers:
      - name: maven
        image: ubuntu:latest
        command:
        - sleep
        args:
        - 99d
      restartPolicy: Never

''') {
  node(POD_LABEL) {
    stage('Get the project') {
      git url: 'https://github.com/Hardcorelevelingwarrior/chap3', branch: 'main'
        }
    
  }
}
  
  