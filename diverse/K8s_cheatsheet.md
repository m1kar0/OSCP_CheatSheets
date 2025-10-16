# Using .yaml config

<code> kubectl apply -f swordfish.yaml  </code>

# Expose ports using LoadBalancer

<code> kubectl expose deployment escape-otus --type=LoadBalancer --name=swordfish-service </code>

# Forward ports from pod to localhost

<code> kubectl get pods </code>

<code> kubectl port-forward escape-otus-7784d74679-h9tqc --address 0.0.0.0 44444:8080 > /dev/null 2>&1 & </code>

This shall forward everything from host on 44444 to 8080 into the pod/container but something must be listening on 8080 as well.

# Clean up

To delete the Service, enter this command:

<code> kubectl delete services my-service </code>

To delete the Deployment, the ReplicaSet, and the Pods that are running the Hello World application, enter this command:

<code>  kubectl delete deployment hello-world </code>
