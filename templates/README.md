# Templates Directory #

Templates for views are stored in this directory.

Templates are saved as html files and used
by Handler classes in main.py in the parent directory.

Information can be added to templates by passing info to them with

`self.render('template.html' info = 'info')`

Then calling for the information in a template expression
block inside the template file:

`<p>  {{info}} was passed to template </p>`

When the template is rendered, it evaluated any expressions
and replaces the expression blocks with the results.
