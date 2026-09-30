require('dotenv').config();
const express=require('express'),Database=require('better-sqlite3'),bcrypt=require('bcryptjs'),jwt=require('jsonwebtoken'),rateLimit=require('express-rate-limit'),helmet=require('helmet');
const SECRET=process.env.JWT_SECRET;if(!SECRET){console.error('Set JWT_SECRET in .env');process.exit(1)}
const db=new Database(process.env.DB_PATH||'./smartmarket.db');db.pragma('foreign_keys=ON');
db.exec(`CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,name TEXT NOT NULL,email TEXT NOT NULL UNIQUE,phone TEXT NOT NULL UNIQUE,password TEXT NOT NULL,location TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY,seller_id INTEGER NOT NULL REFERENCES users(id),title TEXT NOT NULL,description TEXT,category TEXT,brand TEXT,price INTEGER NOT NULL,condition TEXT,location TEXT,status TEXT DEFAULT 'Active',created_at TEXT DEFAULT CURRENT_TIMESTAMP,UNIQUE(seller_id,title,price));`);
if(!db.prepare('SELECT COUNT(*) c FROM products').get().c){ // demo seed (first run only)
 const u=db.prepare('INSERT INTO users(name,email,phone,password,location) VALUES(?,?,?,?,?)').run('SmartMarket Demo','demo@smartmarket.local','0000000000',bcrypt.hashSync(require('crypto').randomBytes(12).toString('hex'),10),'Pune').lastInsertRowid;
 const ins=db.prepare('INSERT INTO products(seller_id,title,description,category,brand,price,condition,location) VALUES(?,?,?,?,?,?,?,?)');
 [['Apple iPhone 13 128GB Blue','Mobiles','Apple',32500,'Used – Good','Pune'],['Dell XPS 13 i7 16GB','Laptops','Dell',52000,'Used – Good','Pune'],['Sony WH-1000XM4 Headphones','Electronics','Sony',14000,'Used – Good','Chennai'],['Solid Wood Study Desk','Furniture','Local',5200,'Used – Good','Pune'],['Canon EOS 200D DSLR Kit','Cameras','Canon',28000,'Used – Good','Delhi'],['PlayStation 5 Disc Edition','Gaming','Sony',36000,'Used – Good','Bengaluru']].forEach(p=>ins.run(u,p[0],'Demo listing',p[1],p[2],p[3],p[4],p[5]));}
const app=express();app.use(helmet({contentSecurityPolicy:false}));app.use(express.json({limit:'100kb'}));
app.use('/api/',rateLimit({windowMs:60000,max:120}));
const s=(v,n=200)=>String(v??'').trim().slice(0,n);
const auth=(q,r,n)=>{try{q.uid=jwt.verify((q.headers.authorization||'').replace('Bearer ',''),SECRET).uid;n()}catch{r.status(401).json({error:'Please log in first.'})}};
const pub=u=>({id:u.id,name:u.name,email:u.email,location:u.location});
app.post('/api/register',(q,r)=>{const{name,email,phone,password,location}=q.body||{};
 if(s(name).length<2||!/^\S+@\S+\.\S+$/.test(s(email))||!/^\d{10}$/.test(s(phone))||s(password,100).length<8)return r.status(400).json({error:'Enter name, valid email, 10-digit mobile and a password of 8+ characters.'});
 if(db.prepare('SELECT 1 FROM users WHERE email=? OR phone=?').get(s(email).toLowerCase(),s(phone)))return r.status(409).json({error:'This email or mobile is already registered. Please log in.'});
 const id=db.prepare('INSERT INTO users(name,email,phone,password,location) VALUES(?,?,?,?,?)').run(s(name,80),s(email).toLowerCase(),s(phone),bcrypt.hashSync(s(password,100),10),s(location,80)).lastInsertRowid;r.json({token:jwt.sign({uid:id},SECRET,{expiresIn:'7d'}),user:pub(db.prepare('SELECT * FROM users WHERE id=?').get(id))})});
app.post('/api/login',(q,r)=>{const u=db.prepare('SELECT * FROM users WHERE email=?').get(s(q.body?.email).toLowerCase());
 if(!u||!bcrypt.compareSync(s(q.body?.password,100),u.password))return r.status(401).json({error:'Wrong email or password. New here? Register first.'});
 r.json({token:jwt.sign({uid:u.id},SECRET,{expiresIn:'7d'}),user:pub(u)})});
app.get('/api/me',auth,(q,r)=>{const u=db.prepare('SELECT * FROM users WHERE id=?').get(q.uid);u?r.json({user:pub(u)}):r.status(401).json({error:'Session expired.'})});
app.get('/api/products',auth,(q,r)=>r.json(db.prepare(`SELECT p.*,u.name seller_name FROM products p JOIN users u ON u.id=p.seller_id WHERE p.status IN('Active','Under Review') OR p.seller_id=? ORDER BY p.id DESC`).all(q.uid)));
app.post('/api/products',auth,(q,r)=>{const b=q.body||{},price=Math.round(+b.price);
 if(s(b.title).length<3||!(price>0))return r.status(400).json({error:'Title and a valid price are required.'});
 const st=['Active','Draft','Under Review'].includes(b.status)?b.status:'Active';
 try{db.prepare('INSERT INTO products(seller_id,title,description,category,brand,price,condition,location,status) VALUES(?,?,?,?,?,?,?,?,?)').run(q.uid,s(b.title,120),s(b.description,1000),s(b.category,40),s(b.brand,40),price,s(b.condition,30),s(b.location,60),st);r.json({ok:true})}
 catch(e){e.code?.startsWith('SQLITE_CONSTRAINT')?r.status(409).json({error:'You already listed this item with the same title and price.'}):r.status(500).json({error:'Server error.'})}});
app.delete('/api/products/:id',auth,(q,r)=>{db.prepare('DELETE FROM products WHERE id=? AND seller_id=?').run(+q.params.id,q.uid);r.json({ok:true})});
app.use(express.static(__dirname+'/public'));
app.listen(process.env.PORT||3000,()=>console.log('SmartMarket AI running'));
