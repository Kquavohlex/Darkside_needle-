
require('dotenv').config();

const express = require('express');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const { Pool } = require('pg');
const nodemailer = require('nodemailer');
const cloudinary = require('cloudinary').v2;

const app = express();

const PORT = process.env.PORT || 3000;

// FRONTEND LOCATION
// server.js is in /server
// index.html is in the repository root
const frontendPath = path.join(__dirname, '..');

const indexPath = path.join(frontendPath, 'index.html');
const adminPath = path.join(frontendPath, 'admin.html');

// ENVIRONMENT VALIDATION
if (!process.env.DATABASE_URL) {
  console.error('ERROR: DATABASE_URL is missing.');
}

if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
  console.error('ERROR: JWT_SECRET must contain at least 32 characters.');
  process.exit(1);
}

// POSTGRESQL DATABASE
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL &&
    !process.env.DATABASE_URL.includes('localhost')
      ? { rejectUnauthorized: false }
      : false
});

pool.on('error', (error) => {
  console.error('Unexpected PostgreSQL error:', error);
});

// SECURITY AND REQUEST MIDDLEWARE
app.disable('x-powered-by');

app.use(helmet({
  contentSecurityPolicy: false
}));

app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));

// Serve frontend assets from repository root
app.use(express.static(frontendPath, {
  index: false
}));

// RATE LIMITING
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false
});

app.use('/api/admin/login', limiter);
app.use('/api/bookings', limiter);

// IMAGE UPLOAD CONFIGURATION
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024,
    files: 4
  },
  fileFilter: (req, file, cb) => {
    const allowed = [
      'image/jpeg',
      'image/png',
      'image/webp'
    ];

    if (!allowed.includes(file.mimetype)) {
      return cb(new Error('Only JPG, PNG and WebP images are allowed.'));
    }

    cb(null, true);
  }
});

// CLOUDINARY CONFIGURATION
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// AUTHENTICATION
function auth(req, res, next) {
  const header = req.headers.authorization || '';

  const token = header.startsWith('Bearer ')
    ? header.slice(7)
    : null;

  if (!token) {
    return res.status(401).json({
      error: 'Authentication required'
    });
  }

  try {
    req.admin = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (error) {
    return res.status(401).json({
      error: 'Session expired. Please log in again.'
    });
  }
}

// INPUT CLEANING
function clean(value, max = 2000) {
  return String(value ?? '').trim().slice(0, max);
}

// EMAIL NOTIFICATIONS
async function notify(subject, textBody, to) {
  if (
    !process.env.SMTP_HOST ||
    !process.env.SMTP_USER ||
    !to
  ) {
    return;
  }

  try {
    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      secure: Number(process.env.SMTP_PORT) === 465,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    });

    await transporter.sendMail({
      from: process.env.SMTP_USER,
      to,
      subject,
      text: textBody
    });

  } catch (error) {
    console.error('Email notification failed:', error.message);
  }
}

// ======================================
// FRONTEND ROUTES
// ======================================

// MAIN WEBSITE
app.get('/', (req, res) => {
  res.sendFile(indexPath);
});

// ADMIN PAGE
app.get('/admin', (req, res) => {
  res.sendFile(adminPath, (error) => {
    if (error) {
      res.status(404).send(
        'Admin page not found. Add admin.html to the repository root.'
      );
    }
  });
});

// ======================================
// API ROUTES
// ======================================

// HEALTH CHECK
app.get('/api/health', (req, res) => {
  res.json({
    ok: true,
    service: 'DARKSIDE_NEEDLE'
  });
});

// PUBLIC CATEGORIES
app.get('/api/categories', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT slug, name, description
       FROM tattoo_categories
       ORDER BY name`
    );

    res.json(result.rows);

  } catch (error) {
    console.error('Categories error:', error.message);

    res.status(500).json({
      error: 'Could not load categories'
    });
  }
});

// PUBLIC GALLERY
app.get('/api/gallery', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, category_slug, title, image_url,
              description, featured
       FROM tattoo_gallery
       ORDER BY featured DESC, created_at DESC`
    );

    res.json(result.rows);

  } catch (error) {
    console.error('Gallery error:', error.message);

    res.status(500).json({
      error: 'Could not load gallery'
    });
  }
});

// PUBLIC TESTIMONIALS
app.get('/api/testimonials', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, display_name, country, rating, review
       FROM testimonials
       WHERE approved = true
       ORDER BY created_at DESC
       LIMIT 30`
    );

    res.json(result.rows);

  } catch (error) {
    console.error('Testimonials error:', error.message);

    res.status(500).json({
      error: 'Could not load reviews'
    });
  }
});

// ======================================
// CUSTOMER APPOINTMENT BOOKING
// ======================================

app.post(
  '/api/bookings',
  upload.array('reference_images', 4),
  async (req, res) => {
    try {
      const b = req.body;

      const required = [
        'full_name',
        'email',
        'phone',
        'country',
        'category',
        'description'
      ];

      for (const field of required) {
        if (!clean(b[field])) {
          return res.status(400).json({
            error: `Please provide ${field.replace('_', ' ')}.`
          });
        }
      }

      if (
        !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
          clean(b.email, 254)
        )
      ) {
        return res.status(400).json({
          error: 'Enter a valid email address.'
        });
      }

      let images = [];

      for (const file of req.files || []) {
        if (
          !process.env.CLOUDINARY_CLOUD_NAME ||
          !process.env.CLOUDINARY_API_KEY ||
          !process.env.CLOUDINARY_API_SECRET
        ) {
          return res.status(503).json({
            error: 'Image uploads are not configured yet.'
          });
        }

        const result = await new Promise((resolve, reject) => {
          const stream = cloudinary.uploader.upload_stream(
            {
              folder: 'darkside-needle/references',
              resource_type: 'image'
            },
            (error, output) => {
              if (error) reject(error);
              else resolve(output);
            }
          );

          stream.end(file.buffer);
        });

        images.push(result.secure_url);
      }

      const reference =
        'DSN-' +
        crypto.randomBytes(4).toString('hex').toUpperCase();

      const values = [
        reference,
        clean(b.full_name, 120),
        clean(b.email, 254).toLowerCase(),
        clean(b.phone, 40),
        clean(b.country, 80),
        clean(b.city, 100),
        clean(b.contact_method, 30),
        clean(b.category, 80),
        clean(b.description, 3000),
        clean(b.placement, 100),
        clean(b.size, 80),
        clean(b.style, 100),
        clean(b.ink_type, 50),
        b.preferred_date || null,
        clean(b.preferred_time, 30),
        clean(b.timezone, 100),
        clean(b.budget, 80),
        JSON.stringify(images),
        clean(b.additional_info, 2000)
      ];

      await pool.query(
        `INSERT INTO appointment_requests(
          reference, full_name, email, phone, country, city,
          contact_method, category, description, placement, size,
          style, ink_type, preferred_date, preferred_time, timezone,
          budget, reference_images, additional_info
        )
        VALUES(
          $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,
          $11,$12,$13,$14,$15,$16,$17,$18::jsonb,$19
        )`,
        values
      );

      await notify(
        'New DARKSIDE_NEEDLE appointment request',
        `New request ${reference}\n` +
        `${values[1]} (${values[2]})\n` +
        `${values[7]} - ${values[8]}`,
        process.env.ADMIN_NOTIFY_EMAIL
      );

      res.status(201).json({
        ok: true,
        reference,
        message:
          'Your request has been received. It is not confirmed until the studio contacts you.'
      });

    } catch (error) {
      console.error('Booking error:', error);

      res.status(500).json({
        error: 'Unable to submit your request. Please try again.'
      });
    }
  }
);

// ======================================
// ADMIN LOGIN
// ======================================

app.post('/api/admin/login', async (req, res) => {
  try {
    const email = clean(req.body.email, 254).toLowerCase();
    const password = String(req.body.password || '');

    if (!email || !password) {
      return res.status(400).json({
        error: 'Email and password are required.'
      });
    }

    const result = await pool.query(
      `SELECT id, email, password_hash
       FROM administrators
       WHERE email = $1`,
      [email]
    );

    if (
      !result.rowCount ||
      !await bcrypt.compare(
        password,
        result.rows[0].password_hash
      )
    ) {
      return res.status(401).json({
        error: 'Invalid email or password'
      });
    }

    const token = jwt.sign(
      {
        id: result.rows[0].id,
        email: result.rows[0].email
      },
      process.env.JWT_SECRET,
      { expiresIn: '8h' }
    );

    res.json({
      token,
      email: result.rows[0].email
    });

  } catch (error) {
    console.error('Admin login error:', error.message);

    res.status(500).json({
      error: 'Login failed'
    });
  }
});

// ======================================
// ADMIN VIEW BOOKINGS
// ======================================

app.get('/api/admin/bookings', auth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT *
       FROM appointment_requests
       ORDER BY created_at DESC`
    );

    res.json(result.rows);

  } catch (error) {
    console.error('Admin bookings error:', error.message);

    res.status(500).json({
      error: 'Could not load bookings'
    });
  }
});

// ======================================
// ADMIN UPDATE BOOKING STATUS
// ======================================

app.patch('/api/admin/bookings/:id', auth, async (req, res) => {
  const allowed = [
    'New Request',
    'Under Review',
    'Accepted',
    'Rejected',
    'Awaiting Customer Response',
    'Confirmed',
    'Completed',
    'Cancelled'
  ];

  const status = clean(req.body.status, 60);

  if (!allowed.includes(status)) {
    return res.status(400).json({
      error: 'Invalid status'
    });
  }

  try {
    const result = await pool.query(
      `UPDATE appointment_requests
       SET status = $1, updated_at = NOW()
       WHERE id = $2
       RETURNING *`,
      [status, req.params.id]
    );

    if (!result.rowCount) {
      return res.status(404).json({
        error: 'Booking not found'
      });
    }

    const booking = result.rows[0];

    await pool.query(
      `INSERT INTO admin_activity_logs(
        admin_id, action, details
      )
      VALUES($1, $2, $3::jsonb)`,
      [
        req.admin.id,
        'booking_status_updated',
        JSON.stringify({
          booking: booking.reference,
          status
        })
      ]
    );

    await notify(
      `DARKSIDE_NEEDLE booking update: ${status}`,
      `Hello ${booking.full_name}, your request ` +
      `${booking.reference} is now: ${status}. ` +
      `The studio will contact you with next steps.`,
      booking.email
    );

    res.json(booking);

  } catch (error) {
    console.error('Update booking error:', error.message);

    res.status(500).json({
      error: 'Could not update booking'
    });
  }
});

// ======================================
// ADMIN DELETE BOOKING
// ======================================

app.delete('/api/admin/bookings/:id', auth, async (req, res) => {
  try {
    const result = await pool.query(
      'DELETE FROM appointment_requests WHERE id = $1',
      [req.params.id]
    );

    if (!result.rowCount) {
      return res.status(404).json({
        error: 'Booking not found'
      });
    }

    res.json({ ok: true });

  } catch (error) {
    console.error('Delete booking error:', error.message);

    res.status(500).json({
      error: 'Could not delete booking'
    });
  }
});

// ======================================
// ADMIN UPLOAD GALLERY IMAGE
// ======================================

app.post(
  '/api/admin/gallery',
  auth,
  upload.single('image'),
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({
          error: 'Select an image'
        });
      }

      if (
        !process.env.CLOUDINARY_CLOUD_NAME ||
        !process.env.CLOUDINARY_API_KEY ||
        !process.env.CLOUDINARY_API_SECRET
      ) {
        return res.status(503).json({
          error: 'Configure Cloudinary before uploading images'
        });
      }

      const output = await new Promise((resolve, reject) => {
        const stream = cloudinary.uploader.upload_stream(
          {
            folder: 'darkside-needle/gallery'
          },
          (error, result) => {
            if (error) reject(error);
            else resolve(result);
          }
        );

        stream.end(req.file.buffer);
      });

      const result = await pool.query(
        `INSERT INTO tattoo_gallery(
          category_slug, title, image_url,
          description, featured
        )
        VALUES($1,$2,$3,$4,$5)
        RETURNING *`,
        [
          clean(req.body.category_slug, 80) || null,
          clean(req.body.title, 120) || 'Tattoo design',
          output.secure_url,
          clean(req.body.description, 1000),
          req.body.featured === 'true'
        ]
      );

      res.status(201).json(result.rows[0]);

    } catch (error) {
      console.error('Gallery upload error:', error.message);

      res.status(500).json({
        error: 'Image upload failed'
      });
    }
  }
);

// ======================================
// ADMIN DELETE GALLERY IMAGE
// ======================================

app.delete('/api/admin/gallery/:id', auth, async (req, res) => {
  try {
    const result = await pool.query(
      'DELETE FROM tattoo_gallery WHERE id = $1',
      [req.params.id]
    );

    if (!result.rowCount) {
      return res.status(404).json({
        error: 'Gallery image not found'
      });
    }

    res.json({ ok: true });

  } catch (error) {
    console.error('Delete gallery error:', error.message);

    res.status(500).json({
      error: 'Could not delete image'
    });
  }
});

// ======================================
// ADMIN ADD TESTIMONIAL
// ======================================

app.post('/api/admin/testimonials', auth, async (req, res) => {
  try {
    const b = req.body;

    if (!clean(b.display_name) || !clean(b.review)) {
      return res.status(400).json({
        error: 'Name and review are required.'
      });
    }

    const result = await pool.query(
      `INSERT INTO testimonials(
        display_name, country, rating, review, approved
      )
      VALUES($1,$2,$3,$4,$5)
      RETURNING *`,
      [
        clean(b.display_name, 80),
        clean(b.country, 80),
        Math.min(5, Math.max(1, Number(b.rating) || 5)),
        clean(b.review, 1500),
        b.approved === true
      ]
    );

    res.status(201).json(result.rows[0]);

  } catch (error) {
    console.error('Add testimonial error:', error.message);

    res.status(500).json({
      error: 'Could not save testimonial'
    });
  }
});

// ======================================
// API NOT FOUND
// ======================================

app.use('/api', (req, res) => {
  res.status(404).json({
    error: 'API endpoint not found'
  });
});

// ======================================
// WEBSITE PAGE NOT FOUND
// ======================================

app.use((req, res) => {
  res.status(404).send('Page not found');
});

// ERROR HANDLER
app.use((error, req, res, next) => {
  console.error('Server error:', error.message);

  if (res.headersSent) {
    return next(error);
  }

  res.status(400).json({
    error: error.message || 'Something went wrong.'
  });
});

// ======================================
// START SERVER
// ======================================

app.listen(PORT, () => {
  console.log(`DARKSIDE_NEEDLE running on port ${PORT}`);
  console.log(`Frontend location: ${indexPath}`);
});
