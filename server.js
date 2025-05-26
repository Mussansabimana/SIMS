const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const initializeDatabase = require("./db.js");
const cors = require('cors');
const PDFDocument = require('pdfkit');
const bcrypt = require('bcryptjs');

const app = express();

// Middleware
app.use(cors({
  origin: "http://localhost:3000",
  methods: ["GET", "POST", "PUT", "DELETE"],
  credentials: true
}));
app.use(express.json());
app.use(cookieParser());
app.use(session({
  secret: '1234',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false,
    maxAge: 24 * 60 * 60 * 1000
  }
}));

let db;

const saltRounds = 10;

// Authentication middleware
const authenticate = (req, res, next) => {
  if (req.session.UsersId) {
    return next();
  }

  return res.status(401).json({ error: 'Unauthorized' });
};

// Helper function to get user ID from session or header
const getUserId = (req) => {
  return req.session.UsersId || req.headers['x-user-id'];
};

// Helper function to log admin actions
async function logAdminAction(UsersID, actionType, details) {
  try {
    await db.run(
      'INSERT INTO Report (UsersID, ReportDate, Summary, Details) VALUES (?, datetime("now"), ?, ?)',
      [UsersID, actionType, details]
    );
  } catch (err) {
    console.error('Error logging admin action:', err);
  }
}

// Users Routes
app.post('/backend-api/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await db.get(
      'SELECT * FROM Users WHERE Username = ?',
      username
    );

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const match = await bcrypt.compare(password, user.Password);

    if (!match) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Update last login
    await db.run(
      'UPDATE Users SET LastLogin = datetime("now") WHERE UsersID = ?',
      user.UsersID
    );

    // Set session
    req.session.UsersId = user.UsersID;
    req.session.role = user.Role;

    res.json({
      message: 'Login successful',
      Users: {
        UsersID: user.UsersID,
        Username: user.Username,
        Role: user.Role
      },
      token: user.UsersID
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/backend-api/signup', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  try {
    // Check if username already exists
    const existingUser = await db.get(
      'SELECT * FROM Users WHERE Username = ?',
      username
    );

    if (existingUser) {
      return res.status(409).json({ error: 'Username already exists' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Insert new user with default role 'user'
    const result = await db.run(
      'INSERT INTO Users (Username, Password, Role) VALUES (?, ?, ?)',
      [username, hashedPassword, 'user']
    );

    // Set session for the new user
    req.session.UsersId = result.lastID;
    req.session.role = 'user';

    res.status(201).json({
      message: 'Signup successful',
      Users: {
        UsersID: result.lastID,
        Username: username,
        Role: 'user'
      },
      token: result.lastID
    });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/backend-api/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).json({ error: 'Logout failed' });
    }
    res.clearCookie('connect.sid');
    res.json({ message: 'Logout successful' });
  });
});

// Spare Part Routes
app.post('/backend-api/spare-parts', authenticate, async (req, res) => {
  const { Name, Category, Quantity, UnitPrice } = req.body;
  const TotalPrice = Quantity * UnitPrice;
  const UsersID = getUserId(req);

  try {
    const result = await db.run(
      'INSERT INTO Spare_Part (Name, Category, Quantity, UnitPrice, TotalPrice) VALUES (?, ?, ?, ?, ?)',
      [Name, Category, Quantity, UnitPrice, TotalPrice]
    );

    // Log the action
    await logAdminAction(
      UsersID,
      'Spare Part Added',
      `Added new spare part: ${Name} (ID: ${result.lastID}), Category: ${Category}, Qty: ${Quantity}, Price: $${UnitPrice}`
    );

    res.status(201).json({
      message: 'Spare part added successfully',
      partId: result.lastID
    });
  } catch (err) {
    console.error('Error adding spare part:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/backend-api/spare-parts', authenticate, async (req, res) => {
  try {
    console.log('Fetching spare parts');
    const rows = await db.all('SELECT * FROM Spare_Part');
    res.json(rows);
  } catch (err) {
    console.error('Error fetching spare parts:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/backend-api/spare-parts/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  const { Name, Category, Quantity, UnitPrice } = req.body;
  const TotalPrice = Quantity * UnitPrice;
  const UsersID = getUserId(req);

  try {
    // Get original part info for logging
    const original = await db.get(
      'SELECT * FROM Spare_Part WHERE PartID = ?',
      [id]
    );

    if (!original) {
      return res.status(404).json({ error: 'Spare part not found' });
    }

    await db.run(
      'UPDATE Spare_Part SET Name = ?, Category = ?, Quantity = ?, UnitPrice = ?, TotalPrice = ? WHERE PartID = ?',
      [Name, Category, Quantity, UnitPrice, TotalPrice, id]
    );

    // Log the action
    await logAdminAction(
      UsersID,
      'Spare Part Updated',
      `Updated spare part: ${Name} (ID: ${id}), Category: ${Category}, Qty: ${Quantity}, Price: $${UnitPrice}`
    );

    res.json({ message: 'Spare part updated successfully' });
  } catch (err) {
    console.error('Error updating spare part:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Stock In Routes
app.post('/backend-api/stock-in', authenticate, async (req, res) => {
  const { PartID, StockInQuantity } = req.body;
  const UsersID = getUserId(req);

  try {
    // First get part info for logging
    const part = await db.get(
      'SELECT Name FROM Spare_Part WHERE PartID = ?',
      [PartID]
    );

    const result = await db.run(
      'INSERT INTO Stock_In (PartID, UsersID, StockInQuantity, StockInDate) VALUES (?, ?, ?, datetime("now"))',
      [PartID, UsersID, StockInQuantity]
    );

    await db.run(
      'UPDATE Spare_Part SET Quantity = Quantity + ?, TotalPrice = (Quantity + ?) * UnitPrice WHERE PartID = ?',
      [StockInQuantity, StockInQuantity, PartID]
    );

    // Log the action
    await logAdminAction(
      UsersID,
      'Stock In',
      `Added ${StockInQuantity} units of ${part.Name} (ID: ${PartID}) to inventory`
    );

    res.status(201).json({
      message: 'Stock in recorded successfully',
      stockInId: result.lastID
    });
  } catch (err) {
    console.error('Error recording stock in:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Stock Out Routes
app.post('/backend-api/stock-out', authenticate, async (req, res) => {
  const { PartID, StockOutQuantity, StockOutUnitPrice } = req.body;
  const UsersID = getUserId(req);
  const StockOutTotalPrice = StockOutQuantity * StockOutUnitPrice;

  try {
    // First get part info for logging
    const part = await db.get(
      'SELECT Name, Quantity FROM Spare_Part WHERE PartID = ?',
      [PartID]
    );

    if (part.Quantity < StockOutQuantity) {
      return res.status(400).json({ error: 'Insufficient stock' });
    }

    const result = await db.run(
      'INSERT INTO Stock_Out (PartID, UsersID, StockOutQuantity, StockOutUnitPrice, StockOutTotalPrice, StockOutDate) VALUES (?, ?, ?, ?, ?, datetime("now"))',
      [PartID, UsersID, StockOutQuantity, StockOutUnitPrice, StockOutTotalPrice]
    );

    await db.run(
      'UPDATE Spare_Part SET Quantity = Quantity - ?, TotalPrice = (Quantity - ?) * UnitPrice WHERE PartID = ?',
      [StockOutQuantity, StockOutQuantity, PartID]
    );

    // Log the action
    await logAdminAction(
      UsersID,
      'Stock Out',
      `Removed ${StockOutQuantity} units of ${part.Name} (ID: ${PartID}) from inventory. Total: $${StockOutTotalPrice}`
    );

    res.status(201).json({
      message: 'Stock out recorded successfully',
      stockOutId: result.lastID
    });
  } catch (err) {
    console.error('Error recording stock out:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET endpoint for stock-in history
app.get('/backend-api/stock-in', authenticate, async (req, res) => {
  try {
    const rows = await db.all(`
      SELECT si.*, sp.Name as PartName, u.Username as UsersName 
      FROM Stock_In si
      JOIN Spare_Part sp ON si.PartID = sp.PartID
      JOIN Users u ON si.UsersID = u.UsersID
      ORDER BY si.StockInDate DESC
    `);
    res.json(rows);
  } catch (err) {
    console.error('Error fetching stock in records:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/backend-api/stock-out', authenticate, async (req, res) => {
  try {
    const rows = await db.all(`
      SELECT so.*, sp.Name as PartName, sp.Category, a.Username as UsersName 
      FROM Stock_Out so
      JOIN Spare_Part sp ON so.PartID = sp.PartID
      JOIN Users a ON so.UsersID = a.UsersID
      ORDER BY so.StockOutDate DESC
    `);
    res.json(rows);
  } catch (err) {
    console.error('Error fetching stock out records:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/backend-api/stock-out/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  const { StockOutQuantity, StockOutUnitPrice } = req.body;
  const StockOutTotalPrice = StockOutQuantity * StockOutUnitPrice;
  const UsersID = getUserId(req);

  try {
    const original = await db.get(
      'SELECT PartID, StockOutQuantity FROM Stock_Out WHERE StockOutID = ?',
      [id]
    );

    if (!original) {
      return res.status(404).json({ error: 'Record not found' });
    }

    const partId = original.PartID;
    const oldQuantity = original.StockOutQuantity;
    const quantityDiff = StockOutQuantity - oldQuantity;

    if (quantityDiff > 0) {
      const part = await db.get(
        'SELECT Quantity FROM Spare_Part WHERE PartID = ?',
        [partId]
      );

      if (part.Quantity < quantityDiff) {
        return res.status(400).json({ error: 'Insufficient stock for update' });
      }
    }

    // Get part info for logging
    const partInfo = await db.get(
      'SELECT Name FROM Spare_Part WHERE PartID = ?',
      [partId]
    );

    await db.run(
      'UPDATE Stock_Out SET StockOutQuantity = ?, StockOutUnitPrice = ?, StockOutTotalPrice = ? WHERE StockOutID = ?',
      [StockOutQuantity, StockOutUnitPrice, StockOutTotalPrice, id]
    );

    await db.run(
      'UPDATE Spare_Part SET Quantity = Quantity - ?, TotalPrice = Quantity * UnitPrice WHERE PartID = ?',
      [quantityDiff, partId]
    );

    // Log the action
    await logAdminAction(
      UsersID,
      'Stock Out Updated',
      `Updated stock out record (ID: ${id}) for ${partInfo.Name}. ` +
      `Old quantity: ${oldQuantity}, New quantity: ${StockOutQuantity}, ` +
      `Total: $${StockOutTotalPrice}`
    );

    res.json({ message: 'Stock out record updated successfully' });
  } catch (err) {
    console.error('Error updating stock out record:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete('/backend-api/stock-out/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  const UsersID = getUserId(req);

  try {
    const record = await db.get(
      'SELECT PartID, StockOutQuantity FROM Stock_Out WHERE StockOutID = ?',
      [id]
    );

    if (!record) {
      return res.status(404).json({ error: 'Record not found' });
    }

    const partId = record.PartID;
    const quantity = record.StockOutQuantity;

    // Get part info for logging
    const partInfo = await db.get(
      'SELECT Name FROM Spare_Part WHERE PartID = ?',
      [partId]
    );

    await db.run(
      'DELETE FROM Stock_Out WHERE StockOutID = ?',
      [id]
    );

    await db.run(
      'UPDATE Spare_Part SET Quantity = Quantity + ?, TotalPrice = Quantity * UnitPrice WHERE PartID = ?',
      [quantity, partId]
    );

    // Log the action
    await logAdminAction(
      UsersID,
      'Stock Out Deleted',
      `Deleted stock out record (ID: ${id}) for ${partInfo.Name}. ` +
      `Restored ${quantity} units to inventory`
    );

    res.json({ message: 'Stock out record deleted successfully' });
  } catch (err) {
    console.error('Error deleting stock out record:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Report Routes
app.get('/backend-api/reports/daily-stock-out', authenticate, async (req, res) => {
  try {
    const today = new Date().toISOString().split('T')[0];
    const rows = await db.all(`
      SELECT 
        so.StockOutID,
        sp.Name as PartName,
        sp.Category,
        so.StockOutQuantity,
        so.StockOutUnitPrice,
        so.StockOutTotalPrice,
        so.StockOutDate as Date,
        a.Username as UsersName
      FROM Stock_Out so
      JOIN Spare_Part sp ON so.PartID = sp.PartID
      JOIN Users a ON so.UsersID = a.UsersID
      WHERE date(so.StockOutDate) = date(?)
      ORDER BY so.StockOutDate DESC
    `, [today]);

    res.json(rows);
  } catch (err) {
    console.error('Error generating daily stock out report:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// New endpoint for all stock out records with date filtering
app.get('/backend-api/reports/all-stock-out', authenticate, async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    let query = `
      SELECT 
        so.StockOutID,
        sp.Name as PartName,
        sp.Category,
        so.StockOutQuantity,
        so.StockOutUnitPrice,
        so.StockOutTotalPrice,
        so.StockOutDate as Date,
        a.Username as UsersName
      FROM Stock_Out so
      JOIN Spare_Part sp ON so.PartID = sp.PartID
      JOIN Users a ON so.UsersID = a.UsersID
    `;
    
    const params = [];
    
    if (startDate && endDate) {
      query += ` WHERE date(so.StockOutDate) BETWEEN date(?) AND date(?)`;
      params.push(startDate, endDate);
    } else if (startDate) {
      query += ` WHERE date(so.StockOutDate) >= date(?)`;
      params.push(startDate);
    } else if (endDate) {
      query += ` WHERE date(so.StockOutDate) <= date(?)`;
      params.push(endDate);
    }
    
    query += ` ORDER BY so.StockOutDate DESC`;
    
    const rows = await db.all(query, params);
    res.json(rows);
  } catch (err) {
    console.error('Error generating all stock out report:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// New endpoint for all stock in records with date filtering
app.get('/backend-api/reports/all-stock-in', authenticate, async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    let query = `
      SELECT 
        si.StockInID,
        sp.Name as PartName,
        sp.Category,
        si.StockInQuantity,
        sp.UnitPrice,
        (si.StockInQuantity * sp.UnitPrice) as TotalPrice,
        si.StockInDate as Date,
        u.Username as UsersName
      FROM Stock_In si
      JOIN Spare_Part sp ON si.PartID = sp.PartID
      JOIN Users u ON si.UsersID = u.UsersID
    `;
    
    const params = [];
    
    if (startDate && endDate) {
      query += ` WHERE date(si.StockInDate) BETWEEN date(?) AND date(?)`;
      params.push(startDate, endDate);
    } else if (startDate) {
      query += ` WHERE date(si.StockInDate) >= date(?)`;
      params.push(startDate);
    } else if (endDate) {
      query += ` WHERE date(si.StockInDate) <= date(?)`;
      params.push(endDate);
    }
    
    query += ` ORDER BY si.StockInDate DESC`;
    
    const rows = await db.all(query, params);
    res.json(rows);
  } catch (err) {
    console.error('Error generating all stock in report:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/backend-api/reports/daily-stock-status', authenticate, async (req, res) => {
  try {
    const today = new Date().toISOString().split('T')[0];
    const rows = await db.all(`
      SELECT 
        sp.PartID,
        sp.Name,
        sp.Category,
        sp.Quantity as CurrentQuantity,
        COALESCE((
          SELECT SUM(si.StockInQuantity) 
          FROM Stock_In si 
          WHERE si.PartID = sp.PartID 
          AND date(si.StockInDate) = date(?)
        ), 0) as TodayIn,
        COALESCE((
          SELECT SUM(so.StockOutQuantity) 
          FROM Stock_Out so 
          WHERE so.PartID = sp.PartID 
          AND date(so.StockOutDate) = date(?)
        ), 0) as TodayOut,
        sp.UnitPrice
      FROM Spare_Part sp
      ORDER BY sp.Name
    `, [today, today]);

    res.json(rows);
  } catch (err) {
    console.error('Error generating daily stock status:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// New endpoint for inventory status with date range
app.get('/backend-api/reports/inventory-status', authenticate, async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    let dateFilter = '';
    const params = [];
    
    if (startDate && endDate) {
      dateFilter = `AND date(si.StockInDate) BETWEEN date(?) AND date(?)`;
      params.push(startDate, endDate);
    } else if (startDate) {
      dateFilter = `AND date(si.StockInDate) >= date(?)`;
      params.push(startDate);
    } else if (endDate) {
      dateFilter = `AND date(si.StockInDate) <= date(?)`;
      params.push(endDate);
    }
    
    const query = `
      SELECT 
        sp.PartID,
        sp.Name,
        sp.Category,
        sp.Quantity as CurrentQuantity,
        COALESCE((
          SELECT SUM(si.StockInQuantity) 
          FROM Stock_In si 
          WHERE si.PartID = sp.PartID 
          ${dateFilter}
        ), 0) as PeriodIn,
        COALESCE((
          SELECT SUM(so.StockOutQuantity) 
          FROM Stock_Out so 
          WHERE so.PartID = sp.PartID 
          ${dateFilter.replace('si.StockInDate', 'so.StockOutDate')}
        ), 0) as PeriodOut,
        sp.UnitPrice,
        sp.TotalPrice
      FROM Spare_Part sp
      ORDER BY sp.Name
    `;
    
    const rows = await db.all(query, params);
    res.json(rows);
  } catch (err) {
    console.error('Error generating inventory status report:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// PDF and CSV report generation routes would follow similar patterns...

async function initializeUsers() {
  try {
    const user = await db.get('SELECT * FROM Users LIMIT 1');

    if (!user) {
      const hashedPassword = await bcrypt.hash('1234', saltRounds);
      const result = await db.run(
        'INSERT INTO Users (Username, Password, Role) VALUES (?, ?, ?)',
        ['admin', hashedPassword, 'admin']
      );
      console.log('Default admin account created: username=admin, password=1234');
    }
  } catch (err) {
    console.error('Error initializing Users account:', err);
  }
}

async function connectDB() {
  try {
    db = await initializeDatabase();
    console.log('Connected to SQLite database');
    await initializeUsers();

    // Start server
    const PORT = 5000;
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  } catch (err) {
    console.error('Database connection failed:', err);
    process.exit(1);
  }
}

connectDB();