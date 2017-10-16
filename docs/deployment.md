# Deployment
Once you are satisfied with any changes and testing,
it's time to deploy the app to gcloud.

There are two steps to deploying the app
for the first time.

1. Create a project on Google Cloud Platform

2. Upload project files

The first step is where you can specify a domain:
either choose a free appspot domain name
or configure your own custom domain

If you choose to use Google's free appspot domain,
you get SSL builtin and don't have to worry about certificates.

For more info about using a custom domain see

http://cloud.google.com/appengine/docs/standard/python/console/using-custom-domains-and-ssl

Login to Google Cloud Platform console

http://console.cloud.google.com

Then, go to the projects page and create a new project.


> **If you're using a free appspot domain: **
> The Project ID is the name of your site and cannot be changed
> once you choose it, so be sure it's the one you want.

> Your domain will look something like this:
> `project-name.appspot.com`
> If project-name is already taken, some letters/numbers
> are added to the name to make it unique
> but the page will tell you if this is the case.

Once the project has been created you
need to tell the gcloud tool which project to use
for deployment. To do this run `gcloud init`
and the tool will walk you through selecting the
newly created project.


The second step involves uploading the code to the project
so the app can start handling requests.

There are 3 YAML files that need to be supplied with the
deploy command to ensure the app works properly.

From the project directory you can run

`gcloud app deploy app.yaml index.yaml cron.yaml`

The other code files are uploaded automatically when
`app.yaml` is parsed by the gcloud tool.

For more info on how app.yaml works
See the `app.yaml` reference here:
http://cloud.google.com/appengine/docs/standard/python/config/appref

Once the deploy command finishes, the app is
serving requests and is up and running!


You should now be able to visit your site and see the front page.

You can then use the google cloud console to manage and monitor the application.