# Init-CRUD-Node-App

Here you can generate CRUD Nodejs application by running the file then you can enter Your Models

Run:
  npm install

Now go to The util/ApiFeatures

in filter() function
you will find this RegExp like a symbol or somthing

just replace it with this

queryStr = queryStr.replace(/\b(gte|gt|lte|lt)\b/g, (match) => "$"+match);


If you like to enter other Models after running the file already
You can run it again and it will automaticly add the new models that you added

I can accept any updates and optimization to improve this library
