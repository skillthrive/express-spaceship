const crypto = require('crypto');
const { promisify } = require('util');
const jwt = require('jsonwebtoken');
const User = require('./../models/userModel');
const catchAsync = require('./../utils/catchAsync');
const AppError = require('./../utils/appError');
const Email = require('./../utils/email');

const signToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
};

const createSendToken = async (user, statusCode, req, res) => {
  const token = signToken(user._id);

  // Generate the random refresh token
  const refreshToken = crypto.randomBytes(32).toString('hex');

  const hashedRefreshToken = crypto
    .createHash('sha256')
    .update(refreshToken)
    .digest('hex');

  const refreshExpiration = new Date().setDate(new Date().getDate() + 28); // 28 days

  res.cookie('spaceshipRefresh', refreshToken, {
    httpOnly: true,
    sameSite: process.env.NODE_ENV == 'production' ? 'none' : 'Lax',
    secure: process.env.NODE_ENV === 'production' ? true : false,
    maxAge: 2419200000, // 28 days
  });

  res.cookie('spaceshipJWT', token, {
    httpOnly: true,
    sameSite: process.env.NODE_ENV == 'production' ? 'none' : 'Lax',
    secure: process.env.NODE_ENV === 'production' ? true : false,
    maxAge: 1800000, // 30 minutes
  });

  await User.findByIdAndUpdate(user._id, {
    $push: {
      refreshTokens: {
        token: hashedRefreshToken,
        expiration: refreshExpiration,
      },
    },
  });

  // Remove password from output
  user.password = undefined;

  res.status(statusCode).json({
    status: 'success',
    token,
    data: {
      user,
    },
  });
};

exports.signup = catchAsync(async (req, res, next) => {
  const newUser = await User.create({
    username: req.body.username,
    email: req.body.email,
    password: req.body.password,
    passwordConfirm: req.body.passwordConfirm,
  });

  const url = `${process.env.HOST}/profile`;
  // console.log(url);
  await new Email(newUser, url).sendWelcome();

  createSendToken(newUser, 201, req, res);
});

exports.login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;

  // 1) Check if email and password exist
  if (!email || !password) {
    return next(new AppError('Please provide email and password!', 400));
  }
  // 2) Check if user exists && password is correct
  const user = await User.findOne({ email }).select('+password');

  if (!user || !(await user.correctPassword(password, user.password))) {
    return next(new AppError('Incorrect email or password', 401));
  }

  // 3) If everything ok, send token to client
  createSendToken(user, 200, req, res);
});

exports.logout = catchAsync(async (req, res) => {
  // Removed refreshTokens from database
  req.user.refreshTokens = [];

  // Set cookies to expired
  res.cookie('spaceshipRefresh', 'loggedout', {
    httpOnly: true,
    sameSite: process.env.NODE_ENV == 'production' ? 'none' : 'Lax',
    secure: process.env.NODE_ENV === 'production' ? true : false,
    maxAge: 0,
  });

  res.cookie('spaceshipJWT', 'loggedout', {
    httpOnly: true,
    sameSite: process.env.NODE_ENV == 'production' ? 'none' : 'Lax',
    secure: process.env.NODE_ENV === 'production' ? true : false,
    maxAge: 0,
  });

  await req.user.save();

  res.status(200).json({
    status: 'success',
    data: {},
  });
});

exports.protect = catchAsync(async (req, res, next) => {
  let token;
  let refresh;

  if (req.cookies && req.cookies.spaceshipJWT) {
    token = req.cookies.spaceshipJWT;
  }

  if (req.cookies && req.cookies.spaceshipRefresh) {
    refresh = req.cookies.spaceshipRefresh;
  }

  if (!token && !refresh) {
    return next(
      new AppError('You are not logged in! Please log in to get access.', 401)
    );
  }

  // Create new token from refresh
  if (!token && refresh) {
    try {
      // Get user based on hashed refresh token
      const hashedRefreshToken = crypto
        .createHash('sha256')
        .update(refresh)
        .digest('hex');

      // Check if user exists with refresh token
      const refreshUser = await User.findOne({
        'refreshTokens.expiration': { $gt: Date.now() },
        'refreshTokens.token': hashedRefreshToken,
      });

      if (!refreshUser) {
        return next(
          new AppError(
            'You are not logged in. Please log in to get access',
            401
          )
        );
      }

      const refreshTokens = refreshUser.refreshTokens;

      const filterToken = refreshTokens.find(({ token }) => token === refresh);

      const filterTokenIat = parseInt(filterToken.issued.getTime() / 1000, 10);

      // Check if user changed password after the refresh was issued
      if (refreshUser.changedPasswordAfter(filterTokenIat)) {
        return next(
          new AppError(
            'User recently changed password! Please log in again.',
            401
          )
        );
      }

      // Create new token
      refreshAuthToken = signToken(refreshUser._id);

      // Send new access token in cookie
      res.cookie('spaceshipJWT', refreshAuthToken, {
        httpOnly: true,
        sameSite: process.env.NODE_ENV == 'production' ? 'none' : 'Lax',
        secure: process.env.NODE_ENV === 'production' ? true : false,
        maxAge: 1800000, // 30 minutes
      });

      // Grant access to protected route
      req.user = refreshUser;
      req.token = refreshAuthToken;
    } catch (err) {
      return next(
        new AppError('You are not logged in! Please log in to get access.', 401)
      );
    }
  }

  if (token) {
    try {
      // Verify token
      const decoded = await promisify(jwt.verify)(
        token,
        process.env.JWT_SECRET
      );

      // Check if user still exists
      const currentUser = await User.findById(decoded.id);
      if (!currentUser) {
        return next(
          new AppError('The user belonging to this token no longer exist.', 401)
        );
      }

      // Check if user changed password after the token was issued
      if (currentUser.changedPasswordAfter(decoded.iat)) {
        return next(
          new AppError(
            'User recently changed password! Please log in again.',
            401
          )
        );
      }

      // Grant access to protected route
      req.user = currentUser;
      res.locals.user = currentUser;
    } catch (err) {
      return next(
        new AppError('You are not logged in! Please log in to get access.', 401)
      );
    }
  }

  next();
});

exports.isLoggedIn = async (req, res, next) => {
  let token;
  let refresh;

  if (req.cookies && req.cookies.spaceshipJWT) {
    token = req.cookies.spaceshipJWT;
  }

  if (req.cookies && req.cookies.spaceshipRefresh) {
    refresh = req.cookies.spaceshipRefresh;
  }

  if (!token && !refresh) {
    return next(
      new AppError('You are not logged in. Please log in to get access', 401)
    );
  }

  // Attempt to get new auth token with refresh
  if (!token && refresh) {
    try {
      // Get user based on hashed refresh token
      const hashedRefreshToken = crypto
        .createHash('sha256')
        .update(refresh)
        .digest('hex');

      // Check if user exists with refresh token
      const refreshUser = await User.findOne({
        'refreshTokens.expiration': { $gt: Date.now() },
        'refreshTokens.token': hashedRefreshToken,
      });

      if (!refreshUser) {
        return next(
          new AppError(
            'You are not logged in. Please log in to get access',
            401
          )
        );
      }

      const refreshTokens = refreshUser.refreshTokens;

      const filterToken = refreshTokens.find(({ token }) => token === refresh);

      const filterTokenIat = parseInt(filterToken.issued.getTime() / 1000, 10);

      // Check if user changed password after the refresh was issued
      if (refreshUser.changedPasswordAfter(filterTokenIat)) {
        return next(
          new AppError(
            'User recently changed password! Please log in again.',
            401
          )
        );
      }

      // Create new token
      const refreshAuthToken = signToken(refreshUser._id);

      // Send new access token in cookie
      res.cookie('spaceshipJWT', refreshAuthToken, {
        httpOnly: true,
        sameSite: process.env.NODE_ENV == 'production' ? 'none' : 'Lax',
        secure: process.env.NODE_ENV === 'production' ? true : false,
        maxAge: 1800000, // 30 minutes
      });

      // There is a logged in user
      res.status(200).json({ status: 'success', data: refreshUser });
    } catch (err) {
      res.status(401).json({ status: 'error', data: null });
    }
  }
  if (token) {
    try {
      // Verify token
      const decoded = await promisify(jwt.verify)(
        req.cookies.spaceshipJWT,
        process.env.JWT_SECRET
      );

      // Check if user still exists
      const currentUser = await User.findById(decoded.id);

      if (!currentUser) {
        return res.status(401).json({ status: 'error', data: null });
      }

      // Check if user changed password after the token was issued
      if (currentUser.changedPasswordAfter(decoded.iat)) {
        return res.status(401).json({ status: 'error', data: null });
      }

      // There is a logged in user
      res.status(200).json({ status: 'success', data: currentUser });
    } catch (err) {
      res.status(401).json({ status: 'error', data: null });
    }
  }
};

exports.restrictTo = (...roles) => {
  return (req, res, next) => {
    // roles ['admin', 'pro', 'user'].
    if (!roles.includes(req.user.role)) {
      return next(
        new AppError('You do not have permission to perform this action', 403)
      );
    }

    next();
  };
};

exports.forgotPassword = catchAsync(async (req, res, next) => {
  // Get user based on email
  const user = await User.findOne({ email: req.body.email });

  if (!user) {
    return next(new AppError('There is no user with email address.', 404));
  }

  // Generate the random reset token
  const resetToken = user.createPasswordResetToken();
  await user.save({ validateBeforeSave: false });

  // Send it to user's email
  try {
    const resetURL = `${process.env.HOST}/reset-password?token=${resetToken}`;
    await new Email(user, resetURL).sendPasswordReset();

    res.status(200).json({
      status: 'success',
      message: 'Token sent to email!',
    });
  } catch (err) {
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save({ validateBeforeSave: false });

    return next(
      new AppError('There was an error sending the email. Try again later!'),
      500
    );
  }
});

exports.resetPassword = catchAsync(async (req, res, next) => {
  // Get user based on the token
  const hashedToken = crypto
    .createHash('sha256')
    .update(req.params.token)
    .digest('hex');

  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: { $gt: Date.now() },
  });

  // If token has not expired, and there is user, set the new password
  if (!user) {
    return next(new AppError('Token is invalid or has expired', 400));
  }
  user.password = req.body.password;
  user.passwordConfirm = req.body.passwordConfirm;
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;
  await user.save();

  // Update changedPasswordAt property for the user
  // Log the user in, send JWT
  createSendToken(user, 200, req, res);
});

exports.updatePassword = catchAsync(async (req, res, next) => {
  // Get user from collection
  const user = await User.findById(req.user.id).select('+password');

  // Check if POSTed current password is correct
  if (!(await user.correctPassword(req.body.passwordCurrent, user.password))) {
    return next(new AppError('Your current password is wrong.', 401));
  }

  // If so, update password
  user.password = req.body.password;
  user.passwordConfirm = req.body.passwordConfirm;
  await user.save();
  // User.findByIdAndUpdate will NOT work as intended!

  // Log user in, send JWT
  createSendToken(user, 200, req, res);
});

exports.emailAvailable = catchAsync(async (req, res, next) => {
  const user = await User.findOne({ email: req.body.email });

  if (user && !req.body.currentEmail) {
    return res.status(200).json({
      status: 'success',
      data: {
        available: false,
      },
    });
  }

  if (user && user.email !== req.body.currentEmail) {
    return res.status(200).json({
      status: 'success',
      data: {
        available: false,
      },
    });
  }

  res.status(200).json({
    status: 'success',
    data: {
      available: true,
    },
  });
});

exports.usernameAvailable = catchAsync(async (req, res, next) => {
  const user = await User.findOne({ username: req.body.username });

  if (user && !req.body.currentUsername) {
    return res.status(200).json({
      status: 'success',
      data: {
        available: false,
      },
    });
  }

  if (user && user.username !== req.body.currentUsername) {
    return res.status(200).json({
      status: 'success',
      data: {
        available: false,
      },
    });
  }

  res.status(200).json({
    status: 'success',
    data: {
      available: true,
    },
  });
});
