const fs = require("fs");
const readline = require("readline");
const moduleData = `const mongoose = require("mongoose");

const Schema = mongoose.Schema(
  {

  },
  { timestamps: true }
);

const %% = mongoose.model("%%", Schema);

module.exports = %%;
`;

const RouterData = `const express = require("express");
const %Controller% = require("../Controllers/%Controller%");

const router = express.Router();

router.route("/").get(%Controller%.index).post(%Controller%.create);

router
  .route("/:id")
  .get(%Controller%.show)
  .patch(%Controller%.update)
  .delete(%Controller%.delete);

module.exports = router;
`;

const ControllerData = `const factory = require("./FactoryHandler");
const %Model% = require("../Models/%Model%");

exports.index = factory.index(%Model%);
exports.create = factory.create(%Model%);
exports.show = factory.show(%Model%);
exports.update = factory.update(%Model%);
exports.delete = factory.delete(%Model%);
`;

String.prototype.plural = function (revert) {
  var plural = {
    "(quiz)$": "$1zes",
    "^(ox)$": "$1en",
    "([m|l])ouse$": "$1ice",
    "(matr|vert|ind)ix|ex$": "$1ices",
    "(x|ch|ss|sh)$": "$1es",
    "([^aeiouy]|qu)y$": "$1ies",
    "(hive)$": "$1s",
    "(?:([^f])fe|([lr])f)$": "$1$2ves",
    "(shea|lea|loa|thie)f$": "$1ves",
    sis$: "ses",
    "([ti])um$": "$1a",
    "(tomat|potat|ech|her|vet)o$": "$1oes",
    "(bu)s$": "$1ses",
    "(alias)$": "$1es",
    "(octop)us$": "$1i",
    "(ax|test)is$": "$1es",
    "(us)$": "$1es",
    "([^s]+)$": "$1s",
  };

  var singular = {
    "(quiz)zes$": "$1",
    "(matr)ices$": "$1ix",
    "(vert|ind)ices$": "$1ex",
    "^(ox)en$": "$1",
    "(alias)es$": "$1",
    "(octop|vir)i$": "$1us",
    "(cris|ax|test)es$": "$1is",
    "(shoe)s$": "$1",
    "(o)es$": "$1",
    "(bus)es$": "$1",
    "([m|l])ice$": "$1ouse",
    "(x|ch|ss|sh)es$": "$1",
    "(m)ovies$": "$1ovie",
    "(s)eries$": "$1eries",
    "([^aeiouy]|qu)ies$": "$1y",
    "([lr])ves$": "$1f",
    "(tive)s$": "$1",
    "(hive)s$": "$1",
    "(li|wi|kni)ves$": "$1fe",
    "(shea|loa|lea|thie)ves$": "$1f",
    "(^analy)ses$": "$1sis",
    "((a)naly|(b)a|(d)iagno|(p)arenthe|(p)rogno|(s)ynop|(t)he)ses$": "$1$2sis",
    "([ti])a$": "$1um",
    "(n)ews$": "$1ews",
    "(h|bl)ouses$": "$1ouse",
    "(corpse)s$": "$1",
    "(us)es$": "$1",
    s$: "",
  };

  var irregular = {
    move: "moves",
    foot: "feet",
    goose: "geese",
    sex: "sexes",
    child: "children",
    man: "men",
    tooth: "teeth",
    person: "people",
  };

  var uncountable = [
    "sheep",
    "fish",
    "deer",
    "moose",
    "series",
    "species",
    "money",
    "rice",
    "information",
    "equipment",
  ];

  // save some time in the case that singular and plural are the same
  if (uncountable.indexOf(this.toLowerCase()) >= 0) return this;

  // check for irregular forms
  for (word in irregular) {
    if (revert) {
      var pattern = new RegExp(irregular[word] + "$", "i");
      var replace = word;
    } else {
      var pattern = new RegExp(word + "$", "i");
      var replace = irregular[word];
    }
    if (pattern.test(this)) return this.replace(pattern, replace);
  }

  if (revert) var array = singular;
  else var array = plural;

  // check for matches using regular expressions
  for (reg in array) {
    var pattern = new RegExp(reg, "i");

    if (pattern.test(this)) return this.replace(pattern, array[reg]);
  }

  return this;
};

if (!fs.existsSync("models")) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });
  let modules = [];
  console.log("Enter Your Models And Type Y When you Are Done :");
  rl.on("line", (line) => {
    if (line.toLowerCase() !== "y") {
      modules.push(line.trim());
    } else {
      if (modules.length != 0) {
        modules = modules.map((moduleName) => {
          return (
            moduleName[0].toUpperCase() + moduleName.slice(1).toLowerCase()
          );
        });
        fs.mkdirSync("Utils");
        fs.mkdirSync("Seeder");
        fs.mkdirSync("public");

        const Routes = modules.map((mymodule) => {
          const module = mymodule.toLowerCase().plural();
          return `\napp.use("/api/${module}", ${mymodule}Router);`;
        });

        const ImportRoutes = modules.map((mymodule) => {
          return `\nconst ${mymodule}Router = require("./Routes/${mymodule}Router")`;
        });

        const index = `const express = require("express");
  const app = express();
  const morgan = require("morgan");
  const GlobalErrorHandler = require("./Controllers/ErrorHandler");
  const cors = require("cors");
  const AppError = require("./utils/AppError");
  const path = require("path");${ImportRoutes.join(" ")}
  
  
  app.use(
    cors({
      origin: "*",
      methods: "GET,HEAD,PUT,PATCH,POST,DELETE",
    })
  );
  app.use(morgan("combined"));
  app.use(express.json({ limit: "10kb" }));
  app.use(express.urlencoded({ extended: true, limit: "10kb" }));
  app.use(express.static(path.join(__dirname, "public")));
  
  ${Routes.join(" ")}
  
  
  app.all("*", (req, res, next) => {
    next(new AppError("Can't find "+req.originalUrl+" on this server", 404));
  });
  
  app.use(GlobalErrorHandler);
  
  module.exports = app;
`;

        const Server = ` 
const mongoose = require("mongoose");
const dotenv = require("dotenv");

process.on("uncaughtException", (err) => {
  console.log("UNCAUGHT EXCEPTION! 💥 Shutting down...");
  console.log(err.name, err.message);
  process.exit(1);
});

dotenv.config({ path: "./.env" });
const app = require("./index.js");

const DB = process.env.DATABASE.replace(
  "<PASSWORD>",
  process.env.DATABASE_PASSWORD
);
mongoose.set("strictQuery", false);
mongoose
  .connect(DB, {
    useNewUrlParser: true,
  })
  .then(() => console.log("DB connection successful!"));

const port = process.env.PORT || 4000;
const server = app.listen(port, () => {
  console.log("App running on port "+port+"...");
});

process.on("unhandledRejection", (err) => {
  console.log("UNHANDLED REJECTION! 💥 Shutting down...");
  console.log(err.name, err.message);
  server.close(() => {
    process.exit(1);
  });
});

process.on("SIGTERM", () => {
  console.log("👋 SIGTERM RECEIVED. Shutting down gracefully");
  server.close(() => {
    console.log("💥 Process terminated!");
  });
});
`;

        const AuthController = `
const { promisify } = require("util");
const jwt = require("jsonwebtoken");
const User = require("../Models/User");
const CatchAsync = require("../utils/CatchAsync");
const AppError = require("../utils/AppError");

const signToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
};

const createSendToken = (user, statusCode, req, res) => {
  const token = signToken(user._id);

  // Remove password from output
  user.password = undefined;

  res.status(statusCode).json({
    status: "success",
    token,
    data: {
      user,
    },
  });
};

exports.signup = CatchAsync(async (req, res, next) => {
  const user = await User.create({
    name: req.body.name,
    email: req.body.email,
    password: req.body.password,
    passwordConfirm: req.body.passwordConfirm,
  });
  createSendToken(user, 201, req, res);
});

exports.login = CatchAsync(async (req, res, next) => {
  const { email, password } = req.body;

  // 1) Check if email and password exist
  if (!email || !password) {
    return next(new AppError("Please provide email and password!", 400));
  }
  // 2) Check if user exists && password is correct
  const user = await User.findOne({ email }).select("+password");

  if (!user || !(await user.correctPassword(password, user.password))) {
    return next(new AppError("Incorrect email or password", 401));
  }

  // 3) If everything ok, send token to client
  createSendToken(user, 200, req, res);
});
0;
exports.logout = (req, res) => {
  res.cookie("jwt", "loggedout", {
    expires: new Date(Date.now() + 10 * 1000),
    httpOnly: true,
  });
  res.status(200).json({ status: "success" });
};

exports.protect = CatchAsync(async (req, res, next) => {
  // 1) Getting token and check of it's there
  let token;
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer")
  ) {
    token = req.headers.authorization.split(" ")[1];
  }
  if (!token) {
    return next(
      new AppError("You are not logged in! Please log in to get access", 401)
    );
  }

  // 2) Verification token
  const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

  // 3) Check if user still exists
  const currentUser = await User.findById(decoded.id);
  if (!currentUser) {
    return next(
      new AppError(
        "The user belonging to this token does no longer exist.",
        401
      )
    );
  }

  //   4) Check if user changed password after the token was issued
  if (currentUser.changedPasswordAfter(decoded.iat)) {
    return next(
      new AppError("User recently changed password! Please log in again.", 401)
    );
  }

  // GRANT ACCESS TO PROTECTED ROUTE
  req.user = currentUser;
  res.locals.user = currentUser;
  next();
});

exports.refresh = CatchAsync(async (req, res, next) => {
  const token = req.headers["x-access-token"];
  if (!token) {
    return res.status(401).json({ auth: false, message: "No token provided" });
  }
  jwtverify(token, process.env.JWT_SECRET, function (err, decoded) {
    if (err) {
      return res
        .status(500)
        .json({ auth: false, message: "Failed to authenticate token" });
    }

    // check expiration
    if (decoded.exp < Date.now() / 1000) {
      // renew token
      const renewToken = jwt.sign(
        {
          data: decoded.data,
        },
        process.env.JWT_SECRET,
        {
          expiresIn: process.env.JWT_EXPIRES_IN,
        }
      );

      // update token
      req.headers["x-access-token"] = renewToken;

      // send new token
      res.status(200).json({ auth: true, token: renewToken });
    } else {
      // send existing token
      res.status(200).json({ auth: true, token: token });
    }
  });
});

exports.restrictTo = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return next(
        new AppError("You do not have permission to perform this action", 403)
      );
    }
    next();
  };
};
`;
        const package = `
{
  "name": "backend",
  "version": "1.0.0",
  "main": "index.js",
  "scripts": {
    "start": "set NODE_ENV=development&& nodemon server.js",
    "prod": "set NODE_ENV=production&& nodemon server.js",
    "seed": "node ./Seeder/DataBaseSeeder.js --seed",
    "fresh": "node ./Seeder/DataBaseSeeder.js --delete && node ./Seeder/DataBaseSeeder.js --seed"
  },
  "author": "",
  "license": "ISC",
  "dependencies": {
    "bcrypt": "^5.1.0",
    "bcryptjs": "^2.4.3",
    "cors": "^2.8.5",
    "dotenv": "^16.0.3",
    "express": "^4.18.2",
    "express-rate-limit": "^6.7.0",
    "jsonwebtoken": "^9.0.0",
    "mongoose": "^6.7.5",
    "morgan": "^1.10.0",
    "multer": "^1.4.5-lts.1",
    "nodemon": "^2.0.20",
    "sharp": "^0.31.3",
    "util": "^0.12.5",
    "validator": "^13.7.0"
  },
  "description": ""
}
`;

        const UserModel = `const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');

const Schema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Please tell us your name!']
  },
  email: {
    type: String,
    required: [true, 'Please provide your email'],
    unique: true,
    lowercase: true,
    validate: [validator.isEmail, 'Please provide a valid email']
  },
  role: {
    type: String,
    enum: ['user', 'guide', 'lead-guide', 'admin'],
    default: 'user'
  },
  password: {
    type: String,
    required: [true, 'Please provide a password'],
    minlength: 8,
    select: false
  },
  passwordConfirm: {
    type: String,
    required: [true, 'Please confirm your password'],
    validate: {
      // This only works on CREATE and SAVE!!!
      validator: function(el) {
        return el === this.password;
      },
      message: 'Passwords are not the same!'
    }
  },
  passwordChangedAt: Date,
  passwordResetToken: String,
  passwordResetExpires: Date,
});
Schema.pre("save", async function (next) {
  // Only run this function if password was actually modified
  if (!this.isModified("password")) return next();

  // Hash the password with cost of 12
  this.password = await bcrypt.hash(this.password, 12);

  // Delete passwordConfirm field
  this.passwordConfirm = undefined;
  next();
});

Schema.pre("save", function (next) {
  if (!this.isModified("password") || this.isNew) return next();

  this.passwordChangedAt = Date.now() - 1000;
  next();
});

Schema.methods.correctPassword = async function (
  candidatePassword,
  userPassword
) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

const User = mongoose.model("User", Schema);

module.exports = User;
`;

        const ApiFeatures = `
class ApiFeatures {
  constructor(query, queryString) {
    this.query = query;
    this.queryString = queryString;
  }

  filter() {
    const queryObj = { ...this.queryString };
    const excludedFields = ["page", "sort", "limit", "fields"];
    excludedFields.forEach((el) => delete queryObj[el]);

    // 1B) Advanced filtering
    let queryStr = JSON.stringify(queryObj);
    queryStr = queryStr.replace(/\b(gte|gt|lte|lt)\b/g, (match) => "$"+match);
    const searchInput = JSON.parse(queryStr) || {};

    const search = Object.keys(searchInput).map((key) => {
      return {
        [key]: { $regex: searchInput[key] },
      };
    });

    let searchData = {};

    if (search[0]) {
      searchData = {
        $or: search,
      };
    }
    console.log(search);
    if (searchInput) {
      this.query = this.query.find(searchData);
    }
    return this;
  }

  sort() {
    if (this.queryString.sort) {
      const sortBy = this.queryString.sort.split(",").join(" ");
      this.query = this.query.sort(sortBy);
    } else {
      this.query = this.query.sort("-createdAt");
    }
    return this;
  }

  limitFields() {
    if (this.queryString.fields) {
      const fields = this.queryString.fields.split(",").join(" ");
      this.query = this.query.select(fields);
    } else {
      this.query = this.query.select("-__v");
    }

    return this;
  }

  paginate() {
    if(this.queryString.page == -1) return this
    const page = this.queryString.page * 1 || 1;
    const limit = this.queryString.limit * 1 || 100;
    const skip = (page - 1) * limit;

    this.query = this.query.skip(skip).limit(limit);

    return this;
  }
}
module.exports = ApiFeatures;
`;

        const CatchAsync = `module.exports = (fn) => {
  return (req, res, next) => {
    fn(req, res, next).catch(next);
  };
};
`;

        const env = `
DATABASE=
DATABASE_Password=
JWT_SECRET=
JWT_EXPIRES_IN=
PORT=
BASE_URL=
`;

        const AppError = `
class AppError extends Error {
  constructor(message, statusCode) {
    super(message);

    this.statusCode = statusCode;
    this.status = statusCode+"".startsWith("4") ? "fail" : "error";
    this.isOperational = true;
    Error.captureStackTrace(this, this.constructor);
  }
}

module.exports = AppError;
`;

        const gitigonre = `
/node_modules
package-lock.json
/.env
`;

        const ErrorHandler = `
const AppError = require("../utils/AppError");

const handleCastErrorDB = (err) => {
  const message = "Invalid "+err.path+":"+err.value+" .";
  return new AppError(message, 400);
};

const handleDuplicateFieldsDB = (err) => {
  const value = err.message.match(/{([^}]*)}/)[1];
  const message = "Duplicate Field Value : "+value+" , Please Try Another value";
  return new AppError(message, 400);
};
const handleValidationErrorDB = (err) => {
  const errors = Object.values(err.errors).map((el) => el.message);
  const message = "Invalid input Data "+errors.join(". ")+"";
  return new AppError(message, 400);
};

const handleJWTError = () =>
  new AppError("Invalid token. Please log in again!", 401);

const handleJWTExpiredError = () =>
  new AppError("Your token has expired! Please log in again.", 401);

const sendErrorDev = (err, res) => {
  return res.status(err.statusCode).json({
    status: err.status,
    error: err,
    message: err.message,
    stack: err.stack,
  });
};

const sendErrorProd = (err, res) => {
  if (err.isOperational) {
    return res.status(err.statusCode).json({
      status: err.status,
      message: err.message,
    });
  }
  console.error("ERROR 💥", err);
  return res.status(500).json({
    status: "error",
    message: "Something went very wrong!",
  });
};

module.exports = (err, req, res, next) => {
  err.statusCode = err.statusCode || 500;
  err.status = err.status || "error";
  if (process.env.NODE_ENV === "development") {
    sendErrorDev(err, res);
  } else if (process.env.NODE_ENV === "production") {
    if (err.name === "CastError") err = handleCastErrorDB(err);
    if (err.code === 11000) err = handleDuplicateFieldsDB(err);
    if (err.name === "ValidationError") err = handleValidationErrorDB(err);
    if (err.name === "JsonWebTokenError") err = handleJWTError();
    if (err.name === "TokenExpiredError") err = handleJWTExpiredError();
    sendErrorProd(err, res);
  }
  res.status(err.statusCode).json({
    status: err.status,
    message: err.message,
  });
};
`;
        const FactoryHandler = `const CatchAsync = require("../utils/CatchAsync");
const AppError = require("../utils/AppError");
const ApiFeatures = require("../utils/ApiFeatures");

exports.delete = (Model) =>
  CatchAsync(async (req, res, next) => {
    const doc = await Model.findByIdAndDelete(req.params.id);

    if (!doc) {
      return next(new AppError("No document found with that ID", 404));
    }

    res.status(204).json({
      status: "success",
      data: null,
    });
  });

exports.update = (Model) =>
  CatchAsync(async (req, res, next) => {
    const doc = await Model.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
      runValidators: true,
    });

    if (!doc) {
      return next(new AppError("No document found with that ID", 404));
    }

    res.status(200).json({
      status: "success",
      doc,
    });
  });

exports.create = (Model) =>
  CatchAsync(async (req, res, next) => {
    const doc = await Model.create(req.body);

    res.status(201).json({
      status: "success",
      doc,
    });
  });

exports.show = (Model) =>
  CatchAsync(async (req, res, next) => {
    const doc = await Model.findById(req.params.id);

    if (!doc) {
      return next(new AppError("No document found with that ID", 404));
    }

    res.status(200).json({
      status: "success",
      doc,
    });
  });

exports.index = (Model) =>
  CatchAsync(async (req, res, next) => {
    let filter = {};
    const features = new ApiFeatures(Model.find(filter), req.query)
      .filter()
      .sort()
      .limitFields()
      .paginate();
    const doc = await features.query;

    res.status(200).json({
      status: "success",
      results: doc.length,
      doc,
    });
  });
`;
        const RequireModels = modules.map((mymodule) => {
          return `\nconst ${mymodule} = require("./../models/${mymodule}")`;
        });
        const ReadFiles = modules.map((mymodule) => {
          const module = mymodule.toLowerCase().plural();
          fs.writeFileSync(`Seeder/${module}.json`, "[]", "utf-8");
          return `\nconst ${module} = JSON.parse(fs.readFileSync(__dirname+"/${module}.json", "utf-8"));`;
        });
        const ImportModel = modules.map((mymodule) => {
          const module = mymodule.toLowerCase().plural();
          return `\nawait ${mymodule}.create(${module})`;
        });
        const DeleteModel = modules.map((mymodule) => {
          return `\nawait ${mymodule}.deleteMany()`;
        });
        const DataBaseSeeder = `const fs = require("fs");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const User = require("../Models/User");
${RequireModels.join(" ")}

dotenv.config({ path: "./.env" });

const DB = process.env.DATABASE.replace(
  "<PASSWORD>",
  process.env.DATABASE_PASSWORD
);
mongoose.set("strictQuery", false);
mongoose
  .connect(DB, {
    useNewUrlParser: true,
  })
  .then(() => console.log("DB connection successful!"));
${ReadFiles.join(" ")}
const users = JSON.parse(fs.readFileSync(__dirname+"/users.json", "utf-8"));


// IMPORT DATA INTO DB
const importData = async () => {
  try {${ImportModel.join(" ")}
    await User.create(users, { validateBeforeSave: false });
    console.log("Data Successfully Inserted !");
  } catch (err) {
    console.log(err);
  }
  process.exit();
};

// DELETE ALL DATA FROM DB
const deleteData = async () => {
  try {
    ${DeleteModel.join(" ")}
    await User.deleteMany();
    console.log("Data Successfully Deleted !");
  } catch (err) {
    console.log(err);
  }
  process.exit();
};

if (process.argv[2] === "--seed") {
  importData();
} else if (process.argv[2] === "--delete") {
  deleteData();
}
`;
        const users = `
[
  {
    "_id": "5c8a1d5b0190b214360dc057",
    "name": "Super Admin",
    "email": "admin@admin.com",
    "role": "Admin",
    "password": 123456
  }
]`;
        modules.forEach((mymodule) => {
          const Modeldata = moduleData.replaceAll("%%", mymodule);
          const Controller_Data = ControllerData.replaceAll(
            "%Model%",
            mymodule
          );
          const Router_Data = RouterData.replaceAll(
            "%Controller%",
            `${mymodule}Controller`
          );
          //**********************Models*****************************/
          fs.mkdirSync("Models", { recursive: true });
          fs.writeFileSync(`Models/${mymodule}.js`, Modeldata, "utf-8");
          //**********************Controllers************************/
          fs.mkdirSync("Controllers", { recursive: true });
          fs.writeFileSync(
            `Controllers/${mymodule}Controller.js`,
            Controller_Data,
            "utf-8"
          );
          //*********************Routes********************************/
          fs.mkdirSync("Routes", { recursive: true });
          fs.writeFileSync(`Routes/${mymodule}Router.js`, Router_Data, "utf-8");
        });
        fs.writeFileSync("index.js", index, "utf-8");
        fs.writeFileSync("server.js", Server, "utf-8");
        fs.writeFileSync("package.json", package, "utf-8");
        fs.writeFileSync(".gitignore", gitigonre, "utf-8");
        fs.writeFileSync(".env", env, "utf-8");
        fs.writeFileSync("Seeder/DataBaseSeeder.js", DataBaseSeeder, "utf-8");
        fs.writeFileSync("Seeder/users.json", users, "utf-8");
        fs.writeFileSync("Models/User.js", UserModel, "utf-8");
        fs.writeFileSync("Utils/ApiFeatures.js", ApiFeatures, "utf-8");
        fs.writeFileSync("Utils/CatchAsync.js", CatchAsync, "utf-8");
        fs.writeFileSync("Utils/AppError.js", AppError, "utf-8");
        fs.writeFileSync("Controllers/ErrorHandler.js", ErrorHandler, "utf-8");
        fs.writeFileSync(
          "Controllers/FactoryHandler.js",
          FactoryHandler,
          "utf-8"
        );
        fs.writeFileSync(
          "Controllers/AuthController.js",
          AuthController,
          "utf-8"
        );
        rl.close();
      } else {
        rl.close();
      }
    }
  });
} else {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });
  let modules = [];
  console.log("Enter Your Models and Type Y when u are Done");
  rl.on("line", (line) => {
    if (line.toLowerCase() !== "y") {
      modules.push(line.trim());
    } else {
      if (modules.length != 0) {
        modules = modules.map((moduleName) => {
          return (
            moduleName[0].toUpperCase() + moduleName.slice(1).toLowerCase()
          );
        });
        const ImportRoutes = modules.map((mymodule) => {
          return `\nconst ${mymodule}Router = require("./Routes/${mymodule}Router")`;
        });
        const Routes = modules.map((mymodule) => {
          const module = mymodule.toLowerCase().plural();
          return `\napp.use("/api/${module}", ${mymodule}Router);`;
        });
        let index = fs.readFileSync("index.js").toString().split("\n");
        index.splice(7, 0, ImportRoutes.join(" "));
        index.splice(21, 0, Routes.join(" "));
        let index_text = index.join("\n");

        fs.writeFile("index.js", index_text, function (err) {
          if (err) return console.log(err);
        });

        const RequireModels = modules.map((mymodule) => {
          return `\nconst ${mymodule} = require("./../models/${mymodule}")`;
        });
        const ReadFiles = modules.map((mymodule) => {
          const module = mymodule.toLowerCase().plural();
          fs.writeFileSync(`Seeder/${module}.json`, "[]", "utf-8");
          return `\nconst ${module} = JSON.parse(fs.readFileSync(__dirname+"/${module}.json", "utf-8"));`;
        });
        const ImportModel = modules.map((mymodule) => {
          const module = mymodule.toLowerCase().plural();
          return `\nawait ${mymodule}.create(${module})`;
        });
        const DeleteModel = modules.map((mymodule) => {
          return `\nawait ${mymodule}.deleteMany()`;
        });

        let seeder = fs
          .readFileSync("Seeder/DataBaseSeeder.js")
          .toString()
          .split("\n");
        seeder.splice(4, 0, RequireModels.join(" "));
        seeder.splice(20, 0, ReadFiles.join(" "));
        seeder.splice(30, 0, ImportModel.join(" "));
        seeder.splice(42, 0, DeleteModel.join(" "));
        let seeder_text = seeder.join("\n");

        fs.writeFile("Seeder/DataBaseSeeder.js", seeder_text, function (err) {
          if (err) return console.log(err);
        });
        modules.forEach((mymodule) => {
          const Modeldata = moduleData.replaceAll("%%", mymodule);
          const Controller_Data = ControllerData.replaceAll(
            "%Model%",
            mymodule
          );
          const Router_Data = RouterData.replaceAll(
            "%Controller%",
            `${mymodule}Controller`
          );
          //**********************Models*****************************/
          fs.writeFileSync(`Models/${mymodule}.js`, Modeldata, "utf-8");
          //**********************Controllers************************/
          fs.writeFileSync(
            `Controllers/${mymodule}Controller.js`,
            Controller_Data,
            "utf-8"
          );
          //*********************Routes********************************/
          fs.writeFileSync(`Routes/${mymodule}Router.js`, Router_Data, "utf-8");
        });
        rl.close();
      } else {
        rl.close();
      }
    }
  });
}
