ROLE assumed 

arn:aws:iam::123456789:role/aws-reserved/sso.amazonaws.com/eu-west-1/AWSReservedSSO_AdministratorAccess_101010

as per docs

```
Important
The role ARN cannot include a path. The format of the role ARN must be arn:aws:iam::<123456789012>:role/<role-name>. 
```

Final result on configmap

arn:aws:iam::123456789:role/AWSReservedSSO_AdministratorAccess_101010

```console
ROLE="    - rolearn: arn:aws:iam::123456789:role/AWSReservedSSO_AdministratorAccess_101010\n      username: EKSROLEACCESS\n      groups:\n        - system:masters"

kubectl get -n kube-system configmap/aws-auth -o yaml | awk "/mapRoles: \|/{print;print \"$ROLE\";next}1" > /tmp/aws-auth-patch.yml

kubectl patch configmap/aws-auth -n kube-system --patch "$(cat /tmp/aws-auth-patch.yml)"
```

```
apiVersion: v1
data:
  mapRoles: |
    - rolearn: arn:aws:iam::123456789:role/AWSReservedSSO_AdministratorAccess_101010
      username: EKSROLEACCESS
      groups:
        - system:masters
 ```
