from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import sqlite3
import hashlib
from datetime import datetime
import os
from functools import wraps

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'admin':
            flash('Access denied. Admins only.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

app = Flask(__name__)
app.secret_key = 'parking_app_secret_key_2025'

DATABASE = 'parking.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()

    
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            address TEXT NOT NULL,
            pin_code TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    
    conn.execute('''
        CREATE TABLE IF NOT EXISTS parking_lots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            address TEXT NOT NULL,
            pin_code TEXT NOT NULL,
            price_per_hour REAL NOT NULL,
            max_spots INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    
    conn.execute('''
        CREATE TABLE IF NOT EXISTS parking_spots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            lot_id INTEGER NOT NULL,
            spot_number INTEGER NOT NULL,
            status TEXT DEFAULT 'available',
            vehicle_number TEXT,
            FOREIGN KEY (lot_id) REFERENCES parking_lots (id)
        )
    ''')

 
    conn.execute('''
        CREATE TABLE IF NOT EXISTS reservations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            spot_id INTEGER NOT NULL,
            lot_id INTEGER NOT NULL,
            vehicle_number TEXT,
            check_in_time TIMESTAMP,
            check_out_time TIMESTAMP,
            total_cost REAL DEFAULT 0,
            status TEXT DEFAULT 'active',
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (spot_id) REFERENCES parking_spots (id),
            FOREIGN KEY (lot_id) REFERENCES parking_lots (id)
        )
    ''')

  
    admin_password = hashlib.sha256('admin123'.encode()).hexdigest()
    conn.execute('''
        INSERT OR IGNORE INTO users 
        (full_name, username, email, password, address, pin_code, role)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (
        'Administrator',        # full_name
        'admin',               # username  
        'admin@parking.com',   # email
        admin_password,        # password
        'Admin Office',        # address
        '000000',             # pin_code
        'admin'               # role
    ))
    
    conn.commit()
    conn.close()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

@app.route('/')
def index():
    if 'user_id' in session:
        if session['role'] == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('user_dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']  # Changed from username to email
        password = hash_password(request.form['password'])

        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE email = ? AND password = ?',  # Changed to email
            (email, password)
        ).fetchone()
        conn.close()

        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['full_name'] = user['full_name']

            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            flash('Invalid email or password', 'error')

    return render_template('login.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        full_name = request.form['full_name'].strip()
        username  = request.form['username'].strip()
        email     = request.form['email'].strip()
        address   = request.form['address'].strip()
        pin_code  = request.form['pin_code'].strip()
        password  = hash_password(request.form['password'])
        
        try:
            conn = get_db_connection()
            conn.execute('''
                INSERT INTO users
                  (full_name, username, email, password, address, pin_code)
                VALUES (?,?,?,?,?,?)
            ''', (full_name, username, email, password, address, pin_code))
            conn.commit()
            flash('Registered! Please login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists', 'error')
        finally:
            conn.close()
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/admin')
def admin_dashboard():
    if 'user_id' not in session or session['role'] != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('login'))

    conn = get_db_connection()

    total_lots = conn.execute('SELECT COUNT(*) as count FROM parking_lots').fetchone()['count']
    total_spots = conn.execute('SELECT COUNT(*) as count FROM parking_spots').fetchone()['count']
    occupied_spots = conn.execute("SELECT COUNT(*) as count FROM parking_spots WHERE status = 'occupied'").fetchone()['count']
    available_spots = total_spots - occupied_spots
    total_users = conn.execute("SELECT COUNT(*) as count FROM users WHERE role = 'user'").fetchone()['count']


    revenue_data = conn.execute('''
        SELECT pl.name, pl.price_per_hour,
               COUNT(r.id) as total_bookings,
               COALESCE(SUM(r.total_cost), 0) as total_revenue
        FROM parking_lots pl
        LEFT JOIN reservations r ON pl.id = r.lot_id AND r.status = 'completed'
        GROUP BY pl.id, pl.name
        ORDER BY total_revenue DESC
    ''').fetchall()


    total_revenue = sum(row['total_revenue'] for row in revenue_data)
    chart_revenue = []
    for row in revenue_data:
        percentage = (row['total_revenue'] / total_revenue * 100) if total_revenue > 0 else 0
        chart_revenue.append({
            'name': row['name'],
            'revenue': row['total_revenue'],
            'percentage': percentage
        })

   
    recent_reservations = conn.execute('''
        SELECT r.*, u.full_name, u.username, pl.name as lot_name, ps.spot_number
        FROM reservations r
        JOIN users u ON r.user_id = u.id
        JOIN parking_lots pl ON r.lot_id = pl.id
        JOIN parking_spots ps ON r.spot_id = ps.id
        WHERE r.status = 'active'
        ORDER BY r.check_in_time DESC
        LIMIT 10
    ''').fetchall()

    conn.close()

    return render_template('admin_dashboard.html', 
                         total_lots=total_lots,
                         total_spots=total_spots,
                         occupied_spots=occupied_spots,
                         available_spots=available_spots,
                         total_users=total_users,
                         recent_reservations=recent_reservations,
                         revenue_data=chart_revenue,
                         total_revenue=total_revenue)

@app.route('/admin/lots')
def admin_lots():
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))

    conn = get_db_connection()
    lots = conn.execute('''
        SELECT pl.*, 
               COUNT(ps.id) as total_spots,
               COUNT(CASE WHEN ps.status = 'occupied' THEN 1 END) as occupied_spots
        FROM parking_lots pl
        LEFT JOIN parking_spots ps ON pl.id = ps.lot_id
        GROUP BY pl.id
        ORDER BY pl.created_at DESC
    ''').fetchall()
    conn.close()

    return render_template('admin_lots.html', lots=lots)

@app.route('/admin/add_lot', methods=['GET', 'POST'])
def add_lot():
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form['name']
        address = request.form['address']
        pin_code = request.form['pin_code']
        price_per_hour = float(request.form['price_per_hour'])
        max_spots = int(request.form['max_spots'])

        conn = get_db_connection()

      
        cursor = conn.execute(
            'INSERT INTO parking_lots (name, address, pin_code, price_per_hour, max_spots) VALUES (?, ?, ?, ?, ?)',
            (name, address, pin_code, price_per_hour, max_spots)
        )
        lot_id = cursor.lastrowid


        for i in range(1, max_spots + 1):
            conn.execute(
                'INSERT INTO parking_spots (lot_id, spot_number) VALUES (?, ?)',
                (lot_id, i)
            )

        conn.commit()
        conn.close()

        flash('Parking lot created successfully!', 'success')
        return redirect(url_for('admin_lots'))

    return render_template('add_lot.html')

@app.route('/admin/edit_lot/<int:lot_id>', methods=['GET', 'POST'])
def edit_lot(lot_id):
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))

    conn = get_db_connection()

    if request.method == 'POST':
        name = request.form['name']
        address = request.form['address']
        pin_code = request.form['pin_code']
        price_per_hour = float(request.form['price_per_hour'])
        max_spots = int(request.form['max_spots'])

        # Get current max spots
        current_lot = conn.execute('SELECT max_spots FROM parking_lots WHERE id = ?', (lot_id,)).fetchone()
        current_max = current_lot['max_spots']

        # Update lot
        conn.execute(
            'UPDATE parking_lots SET name = ?, address = ?, pin_code = ?, price_per_hour = ?, max_spots = ? WHERE id = ?',
            (name, address, pin_code, price_per_hour, max_spots, lot_id)
        )

        # Adjust spots if needed
        if max_spots > current_max:
            for i in range(current_max + 1, max_spots + 1):
                conn.execute(
                    'INSERT INTO parking_spots (lot_id, spot_number) VALUES (?, ?)',
                    (lot_id, i)
                )
        elif max_spots < current_max:
            conn.execute(
                'DELETE FROM parking_spots WHERE lot_id = ? AND spot_number > ? AND status = "available"',
                (lot_id, max_spots)
            )

        conn.commit()
        conn.close()

        flash('Parking lot updated successfully!', 'success')
        return redirect(url_for('admin_lots'))

    lot = conn.execute('SELECT * FROM parking_lots WHERE id = ?', (lot_id,)).fetchone()
    conn.close()

    return render_template('edit_lot.html', lot=lot)

@app.route('/admin/spots_overview')
@admin_required
def spots_overview():
    db = get_db_connection()
    # Fetch all lots and their spots
    lots = db.execute('SELECT * FROM parking_lots ORDER BY name').fetchall()
    overview = []
    for lot in lots:
        spots = db.execute(
            'SELECT id, status, spot_number FROM parking_spots WHERE lot_id = ? ORDER BY spot_number',
            (lot['id'],)
        ).fetchall()
        overview.append({
            'lot': dict(lot),
            'spots': [dict(spot) for spot in spots]
        })
    db.close()
    return render_template('admin_spots_overview.html', overview=overview)

@app.route('/admin/lots/<int:lot_id>/spots/<int:spot_id>')
@admin_required
def view_delete_spot(lot_id, spot_id):
    db = get_db_connection()
    spot = db.execute(
        'SELECT ps.id, ps.spot_number, ps.status, pl.name AS lot_name '
        'FROM parking_spots ps JOIN parking_lots pl ON ps.lot_id=pl.id '
        'WHERE ps.id = ?', (spot_id,)
    ).fetchone()
    db.close()
    if not spot:
        flash('Spot not found', 'error')
        return redirect(url_for('spots_overview'))
    return render_template('admin_view_delete_spot.html', spot=dict(spot))

@app.route('/admin/delete_lot/<int:lot_id>')
def delete_lot(lot_id):
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))

    conn = get_db_connection()

    # Check if any spots are occupied
    occupied = conn.execute(
        "SELECT COUNT(*) as count FROM parking_spots WHERE lot_id = ? AND status = 'occupied'",
        (lot_id,)
    ).fetchone()['count']

    if occupied > 0:
        flash('Cannot delete lot with occupied spots', 'error')
    else:
        conn.execute('DELETE FROM parking_spots WHERE lot_id = ?', (lot_id,))
        conn.execute('DELETE FROM parking_lots WHERE id = ?', (lot_id,))
        conn.commit()
        flash('Parking lot deleted successfully!', 'success')

    conn.close()
    return redirect(url_for('admin_lots'))

@app.route('/admin/spots/<int:spot_id>/details')
@admin_required
def occupied_details(spot_id):
    db = get_db_connection()
    details = db.execute('''
        SELECT r.id AS reservation_id, r.user_id, u.full_name, r.vehicle_number,
               r.check_in_time, r.check_out_time, r.total_cost, r.spot_id
        FROM reservations r
        JOIN users u ON r.user_id=u.id
        WHERE r.spot_id=? AND r.status='active'
    ''', (spot_id,)).fetchone()
    db.close()
    if not details:
        flash('No active reservation for this spot', 'error')
        return redirect(url_for('view_delete_spot', lot_id=0, spot_id=spot_id))
    return render_template('admin_occupied_details.html', d=dict(details))

@app.route('/admin/spots')
def admin_spots():
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))

    conn = get_db_connection()
    spots = conn.execute('''
        SELECT ps.*, pl.name as lot_name, 
               u.full_name as user_name, u.username,
               r.check_in_time, r.total_cost
        FROM parking_spots ps
        JOIN parking_lots pl ON ps.lot_id = pl.id
        LEFT JOIN reservations r ON ps.id = r.spot_id AND r.status = 'active'
        LEFT JOIN users u ON r.user_id = u.id
        ORDER BY pl.name, ps.spot_number
    ''').fetchall()
    conn.close()

    return render_template('admin_spots.html', spots=spots)

@app.route('/profile')
def view_profile():
    if 'user_id' not in session:
        flash('Please login to view your profile', 'error')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    user = conn.execute(
        'SELECT * FROM users WHERE id = ?',
        (session['user_id'],)
    ).fetchone()
    conn.close()
    
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('logout'))
    
    return render_template('profile.html', user=dict(user))

@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session:
        flash('Please login to edit your profile', 'error')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    if request.method == 'POST':
        # Get form data
        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip()
        username = request.form.get('username', '').strip()
        address = request.form.get('address', '').strip()
        pin_code = request.form.get('pin_code', '').strip()
        current_password = request.form.get('current_password', '').strip()
        new_password = request.form.get('new_password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        
        
        if not all([full_name, email, username, address, pin_code]):
            flash('Please fill in all required fields', 'error')
            return redirect(url_for('edit_profile'))
        
       
        user = conn.execute(
            'SELECT * FROM users WHERE id = ?',
            (session['user_id'],)
        ).fetchone()
        
 
        if new_password:
            if not current_password:
                flash('Current password is required to set a new password', 'error')
                return redirect(url_for('edit_profile'))
            
            if hash_password(current_password) != user['password']:
                flash('Current password is incorrect', 'error')
                return redirect(url_for('edit_profile'))
            
            if new_password != confirm_password:
                flash('New passwords do not match', 'error')
                return redirect(url_for('edit_profile'))
            
            if len(new_password) < 6:
                flash('New password must be at least 6 characters long', 'error')
                return redirect(url_for('edit_profile'))
        
        try:

            if new_password:
                
                conn.execute('''
                    UPDATE users 
                    SET full_name = ?, email = ?, username = ?, password = ?, address = ?, pin_code = ?
                    WHERE id = ?
                ''', (full_name, email, username, hash_password(new_password), address, pin_code, session['user_id']))
                flash('Profile and password updated successfully!', 'success')
            else:
                
                conn.execute('''
                    UPDATE users 
                    SET full_name = ?, email = ?, username = ?, address = ?, pin_code = ?
                    WHERE id = ?
                ''', (full_name, email, username, address, pin_code, session['user_id']))
                flash('Profile updated successfully!', 'success')
            
            conn.commit()
            
            
            session['username'] = username
            session['full_name'] = full_name
            
            return redirect(url_for('view_profile'))
            
        except sqlite3.IntegrityError:
            flash('Email or username already exists', 'error')
        except Exception as e:
            flash('An error occurred while updating your profile', 'error')
    
    user = conn.execute(
        'SELECT * FROM users WHERE id = ?',
        (session['user_id'],)
    ).fetchone()
    conn.close()
    
    return render_template('edit_profile.html', user=dict(user))

@app.route('/admin/users')
@admin_required
def admin_users():
    conn = get_db_connection()
    users = conn.execute('''
        SELECT id, full_name, username, email, address, pin_code, created_at
        FROM users
        WHERE role='user'
        ORDER BY created_at DESC
    ''').fetchall()
    conn.close()
    return render_template('admin_users.html', users=users)

@app.route('/user')
def user_dashboard():
    if 'user_id' not in session or session['role'] != 'user':
        flash('Access denied', 'error')
        return redirect(url_for('login'))

    conn = get_db_connection()

    
    active_reservation = conn.execute('''
        SELECT r.*, pl.name as lot_name, pl.address, pl.price_per_hour,
               ps.spot_number, ps.id as spot_id
        FROM reservations r
        JOIN parking_lots pl ON r.lot_id = pl.id
        JOIN parking_spots ps ON r.spot_id = ps.id
        WHERE r.user_id = ? AND r.status = 'active'
    ''', (session['user_id'],)).fetchone()

    
    all_reservations = conn.execute('''
        SELECT r.*, pl.name as lot_name, ps.spot_number, pl.price_per_hour
        FROM reservations r
        JOIN parking_lots pl ON r.lot_id = pl.id
        JOIN parking_spots ps ON r.spot_id = ps.id
        WHERE r.user_id = ?
        ORDER BY r.check_in_time DESC
        LIMIT 20
    ''', (session['user_id'],)).fetchall()

 
    parking_summary = conn.execute('''
        SELECT 
            COUNT(*) as total_bookings,
            COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed_bookings,
            COUNT(CASE WHEN status = 'active' THEN 1 END) as active_bookings,
            COUNT(CASE WHEN status = 'cancelled' THEN 1 END) as cancelled_bookings,
            COALESCE(SUM(total_cost), 0) as total_spent
        FROM reservations
        WHERE user_id = ?
    ''', (session['user_id'],)).fetchone()

 
    if parking_summary and parking_summary['total_bookings'] > 0:
        parking_summary = dict(parking_summary)
        parking_summary['completed_percentage'] = (parking_summary['completed_bookings'] / parking_summary['total_bookings']) * 100
        parking_summary['active_percentage'] = (parking_summary['active_bookings'] / parking_summary['total_bookings']) * 100
        parking_summary['cancelled_percentage'] = (parking_summary['cancelled_bookings'] / parking_summary['total_bookings']) * 100
    else:
        parking_summary = None


    available_lots = conn.execute('''
        SELECT pl.*, 
               COUNT(ps.id) as total_spots,
               COUNT(CASE WHEN ps.status = 'available' THEN 1 END) as available_spots
        FROM parking_lots pl
        LEFT JOIN parking_spots ps ON pl.id = ps.lot_id
        GROUP BY pl.id
        HAVING available_spots > 0
        ORDER BY pl.name
    ''').fetchall()

    conn.close()


    active_reservation = dict(active_reservation) if active_reservation else None
    all_reservations = [dict(r) for r in all_reservations]
    available_lots = [dict(l) for l in available_lots]

    return render_template('user_dashboard.html', 
                         active_reservation=active_reservation,
                         all_reservations=all_reservations,
                         parking_summary=parking_summary,
                         available_lots=available_lots)


@app.route('/release_parking/<int:reservation_id>')
def release_parking_form(reservation_id):
    if 'user_id' not in session or session['role'] != 'user':
        return redirect(url_for('login'))

    conn = get_db_connection()

 
    reservation = conn.execute('''
        SELECT r.*, pl.name as lot_name, pl.price_per_hour, ps.spot_number
        FROM reservations r
        JOIN parking_lots pl ON r.lot_id = pl.id
        JOIN parking_spots ps ON r.spot_id = ps.id
        WHERE r.id = ? AND r.user_id = ? AND r.status = 'active'
    ''', (reservation_id, session['user_id'])).fetchone()

    if not reservation:
        flash('Reservation not found', 'error')
        conn.close()
        return redirect(url_for('user_dashboard'))


    check_in = datetime.fromisoformat(reservation['check_in_time'])
    now = datetime.now()
    duration = now - check_in
    duration_hours = max(1, int(duration.total_seconds() / 3600))
    estimated_cost = duration_hours * reservation['price_per_hour']

    conn.close()

    return render_template('release_parking_form.html', 
                         reservation=dict(reservation),
                         duration_hours=duration_hours,
                         estimated_cost=estimated_cost)


@app.route('/release_spot/<int:reservation_id>', methods=['POST'])
def release_spot(reservation_id):
    if 'user_id' not in session or session['role'] != 'user':
        return redirect(url_for('login'))

    conn = get_db_connection()


    reservation = conn.execute('''
        SELECT r.*, pl.price_per_hour
        FROM reservations r
        JOIN parking_lots pl ON r.lot_id = pl.id
        WHERE r.id = ? AND r.user_id = ? AND r.status = "active"
    ''', (reservation_id, session['user_id'])).fetchone()

    if not reservation:
        flash('Reservation not found', 'error')
        conn.close()
        return redirect(url_for('user_dashboard'))

    check_in = datetime.fromisoformat(reservation['check_in_time'])
    check_out = datetime.now()
    duration = check_out - check_in
    duration_hours = max(1, int(duration.total_seconds() / 3600))
    total_cost = duration_hours * reservation['price_per_hour']


    conn.execute(
        'UPDATE reservations SET check_out_time = ?, total_cost = ?, status = "completed" WHERE id = ?',
        (check_out, total_cost, reservation_id)
    )

    # Free the spot
    conn.execute(
        'UPDATE parking_spots SET status = "available" WHERE id = ?',
        (reservation['spot_id'],)
    )

    conn.commit()
    conn.close()

    flash(f'Parking spot released successfully! Total cost: ₹{total_cost:.2f}', 'success')
    return redirect(url_for('user_dashboard'))

@app.route('/book_spot/<int:lot_id>')
def book_spot(lot_id):
    if 'user_id' not in session or session['role'] != 'user':
        return redirect(url_for('login'))

    conn = get_db_connection()


    existing = conn.execute(
        'SELECT id FROM reservations WHERE user_id = ? AND status = "active"',
        (session['user_id'],)
    ).fetchone()

    if existing:
        flash('You already have an active reservation', 'error')
        conn.close()
        return redirect(url_for('user_dashboard'))


    available_spot = conn.execute(
        'SELECT id FROM parking_spots WHERE lot_id = ? AND status = "available" ORDER BY spot_number LIMIT 1',
        (lot_id,)
    ).fetchone()

    if not available_spot:
        flash('No available spots in this lot', 'error')
        conn.close()
        return redirect(url_for('user_dashboard'))


    spot_id = available_spot['id']
    check_in_time = datetime.now()

    conn.execute(
        'INSERT INTO reservations (user_id, spot_id, lot_id, check_in_time, status) VALUES (?, ?, ?, ?, ?)',
        (session['user_id'], spot_id, lot_id, check_in_time, 'active')
    )

    conn.execute(
        'UPDATE parking_spots SET status = "occupied" WHERE id = ?',
        (spot_id,)
    )

    conn.commit()
    conn.close()

    flash('Parking spot booked successfully!', 'success')
    return redirect(url_for('user_dashboard'))

@app.route('/reserve_parking_history')
def reserve_parking_history():
    if 'user_id' not in session or session['role'] != 'user':
        return redirect(url_for('login'))

    conn = get_db_connection()
    reservations = conn.execute('''
        SELECT r.*, pl.name as lot_name, ps.spot_number
        FROM reservations r
        JOIN parking_lots pl ON r.lot_id = pl.id
        JOIN parking_spots ps ON r.spot_id = ps.id
        WHERE r.user_id = ?
        ORDER BY r.check_in_time DESC
    ''', (session['user_id'],)).fetchall()
    conn.close()

    return render_template('reserve_parking_history.html', reservations=[dict(r) for r in reservations])

@app.route('/search', methods=['GET', 'POST'])
def search():
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))

    results = []
    search_term = ''

    if request.method == 'POST':
        search_term = request.form['search_term']
        conn = get_db_connection()

        # Search users
        users = conn.execute(
            'SELECT "user" as type, username, full_name as name, email FROM users WHERE username LIKE ? OR full_name LIKE ? OR email LIKE ?',
            (f'%{search_term}%', f'%{search_term}%', f'%{search_term}%')
        ).fetchall()

        # Search lots
        lots = conn.execute(
            'SELECT "lot" as type, name, address, pin_code FROM parking_lots WHERE name LIKE ? OR address LIKE ? OR pin_code LIKE ?',
            (f'%{search_term}%', f'%{search_term}%', f'%{search_term}%')
        ).fetchall()

        results = list(users) + list(lots)
        conn.close()

    return render_template('search.html', results=results, search_term=search_term)

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
