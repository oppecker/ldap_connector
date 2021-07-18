$containers = docker ps -a --format "{{.Names}}"
foreach ($name in $containers)
{
  Write-Output "DELETING CONTAINER: $name"
  docker rm -f $name
}

$images = docker images --format "{{.Repository}}"
foreach ($image in $images)
{
	if ($image -ne 'python')
	{
	  Write-Output "DELETING IMAGE: $image"
		docker image rm $image -f
	}
}
