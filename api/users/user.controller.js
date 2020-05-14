const {
  create,
  getUserById,
  getUsers,
  updateUser,
  deleteUser,
  getUserByEmail,
} = require("./user.service");
const { genSaltSync, hashSync, compareSync } = require("bcrypt");
const { sign } = require("jsonwebtoken");

module.exports = {
  createUser: (req, res) => {
    const body = req.body;
    const saltRounds = 10;
    const salt = genSaltSync(saltRounds);
    body.password = hashSync(body.password, salt);
    create(body, (error, results) => {
      if (error) {
        return res.status(500).json({
          success: 0,
          message: "Database connection error",
        });
      }
      return res.status(200).json({
        success: 1,
        data: results,
      });
    });
  },
  getUserById: (req, res) => {
    const id = req.params.id;
    getUserById(id, (error, results) => {
      if (error) {
        return res.status(500).json({
          success: 0,
          message: "Database error",
        });
      }
      if (!results) {
        return res.status(404).json({
          success: 0,
          message: "Record not found",
        });
      }
      return res.status(200).json({
        success: 1,
        data: results,
      });
    });
  },
  getUsers: (req, res) => {
    getUsers((error, results) => {
      if (error) {
        return res.status(500).json({
          success: 0,
          message: "Database error",
        });
      }
      if (!results) {
        return res.status(404).json({
          success: 0,
          message: "No users",
        });
      }
      return res.status(200).json({
        success: 1,
        data: results,
      });
    });
  },
  updateUser: (req, res) => {
    const body = req.body;
    const saltRounds = 10;
    const salt = bcrypt.genSaltSync(saltRounds);
    body.password = bcrypt.hashSync(body.password, salt);
    updateUser(body, (error, results) => {
      if (error) {
        return res.status(500).json({
          success: 0,
          message: "Database connection error",
        });
      }
      if (!results) {
        return res.status(500).json({
          success: 0,
          message: "Failed to update user",
        });
      }
      return res.status(200).json({
        success: 1,
        message: "User updated successfully",
      });
    });
  },
  deleteUser: (req, res) => {
    const body = req.body;
    deleteUser(body, (error, results) => {
      if (error) {
        return res.status(500).json({
          success: 0,
          message: "Database connection error",
        });
      }
      if (!results) {
        return res.status(404).json({
          success: 0,
          message: "Record not found",
        });
      }
      return res.status(200).json({
        success: 1,
        message: "User successfully deleted",
      });
    });
  },
  login: (req, res) => {
    const body = req.body;
    getUserByEmail(body.email, (error, results) => {
      if (error) {
        return res.status(500).json({
          success: 0,
          message: "Database connection error",
        });
      }

      if (!results) {
        return res.status(404).json({
          success: 0,
          message: "Invalid email or password",
        });
      }
      const result = compareSync(body.password, results.password);
      console.log("result", result);
      if (result) {
        results.password = undefined;
        const jsontoken = sign({ result: results }, process.env.JWT_KEY, {
          expiresIn: "1h",
        });
        return res.status(200).json({
          success: 1,
          message: "login successfully",
          token: jsontoken,
        });
      } else {
        return res.status(404).json({
          success: 0,
          message: "Invalid email or password",
        });
      }
    });
  },
};
