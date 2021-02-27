const crypto = require('crypto');
const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');

const refreshToken = new mongoose.Schema({
  token: {
    type: String,
    trim: true,
  },
  expiration: {
    type: Date,
  },
  issued: {
    type: Date,
    default: Date.now(),
  },
  select: false,
});

const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: [true, 'Please pick a username!'],
      unique: true,
      validate: {
        // This only works on CREATE and SAVE!!!
        // Validate username: 4-20 characters, no . or _ at beg, middle, ends
        validator: function (el) {
          return /^(?=.{1,20}$)(?![_.])(?!.*[_.]{2})[a-zA-Z0-9._]+(?<![_.])$/.test(
            el
          );
        },
        message: 'Please provide a valid username',
      },
    },
    email: {
      type: String,
      required: [true, 'Please provide your email'],
      unique: true,
      lowercase: true,
      validate: [validator.isEmail, 'Please provide a valid email'],
    },
    photo: {
      type: String,
      default: 'default.jpg',
    },
    role: {
      type: String,
      enum: ['user', 'pro', 'admin'],
      default: 'user',
    },
    customerId: {
      type: String,
    },
    password: {
      type: String,
      required: [true, 'Please provide a password'],
      validate: {
        // This only works on CREATE and SAVE!!!
        // Validate password: at least 8 characters, one lower, one upper, one number, one special, no whitespace
        validator: function (el) {
          return /^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$/.test(
            el
          );
        },
        message: 'Please provide a valid password',
      },
      select: false,
    },
    passwordConfirm: {
      type: String,
      required: [true, 'Please confirm your password'],
      validate: {
        // This only works on CREATE and SAVE!!!
        validator: function (el) {
          return el === this.password;
        },
        message: 'Passwords are not the same!',
      },
    },
    passwordChangedAt: {
      type: Date,
    },
    passwordResetToken: {
      type: String,
    },
    passwordResetExpires: {
      type: Date,
    },
    active: {
      type: Boolean,
      default: true,
      select: false,
    },
    refreshTokens: {
      type: [refreshToken],
    },
  },
  { timestamps: true, toJSON: { virtuals: true }, toObject: { virtuals: true } }
);

// Virtual populate
userSchema.virtual('memberships', {
  ref: 'Membership',
  foreignField: 'member',
  localField: 'id',
});

userSchema.pre('save', async function (next) {
  // Only run this function if password was actually modified
  if (!this.isModified('password')) return next();

  // Hash the password with cost of 12
  this.password = await bcrypt.hash(this.password, 12);

  // Delete passwordConfirm field
  this.passwordConfirm = undefined;
  next();
});

userSchema.pre('save', function (next) {
  if (!this.isModified('password') || this.isNew) return next();

  this.passwordChangedAt = Date.now() - 1000;
  next();
});

userSchema.pre(/^find/, function (next) {
  // this points to the current query
  this.find({ active: { $ne: false } });
  next();
});

userSchema.methods.correctPassword = async function (
  candidatePassword,
  userPassword
) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

userSchema.methods.changedPasswordAfter = function (JWTTimestamp) {
  if (this.passwordChangedAt) {
    const changedTimestamp = parseInt(
      this.passwordChangedAt.getTime() / 1000,
      10
    );

    return JWTTimestamp < changedTimestamp;
  }

  // False means NOT changed
  return false;
};

userSchema.methods.createRefreshToken = function () {
  const refreshToken = crypto.randomBytes(32).toString('hex');
  this.authRefreshToken = crypto
    .createHash('sha256')
    .update(refreshToken)
    .digest('hex');

  this.authRefreshExpires = new Date().setDate(new Date().getDate() + 7);

  return refreshToken;
};

userSchema.methods.createPasswordResetToken = function () {
  const resetToken = crypto.randomBytes(32).toString('hex');

  this.passwordResetToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');

  this.passwordResetExpires = Date.now() + 10 * 60 * 1000;

  return resetToken;
};

const User = mongoose.model('User', userSchema);

module.exports = User;
