from fastapi import FastAPI, APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional
import uuid
from datetime import datetime, timezone
import bcrypt
import jwt
from decimal import Decimal

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGODB_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# JWT configuration
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-secret-key-change-in-production')
JWT_ALGORITHM = 'HS256'

# Security
security = HTTPBearer()

# Create the main app without a prefix
app = FastAPI(title="MicroMart E-Commerce API")

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# User Service Models
class UserCreate(BaseModel):
    email: EmailStr
    password: str
    first_name: str
    last_name: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class User(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: EmailStr
    first_name: str
    last_name: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class UserResponse(BaseModel):
    user: User
    token: str

# Product Service Models
class Product(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    price: float
    image_url: str
    category: str
    stock: int
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class ProductCreate(BaseModel):
    name: str
    description: str
    price: float
    image_url: str
    category: str
    stock: int

# Cart Service Models
class CartItem(BaseModel):
    product_id: str
    quantity: int
    price: float

class Cart(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    items: List[CartItem] = []
    total: float = 0.0
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class AddToCartRequest(BaseModel):
    product_id: str
    quantity: int

# Order Service Models
class OrderItem(BaseModel):
    product_id: str
    product_name: str
    quantity: int
    price: float

class Order(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    items: List[OrderItem]
    total: float
    status: str = "pending"
    shipping_address: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class OrderCreate(BaseModel):
    shipping_address: str

# Payment Service Models
class Payment(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    order_id: str
    amount: float
    status: str = "pending"
    payment_method: str = "mock"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

# Helper functions
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_jwt_token(user_id: str) -> str:
    payload = {"user_id": user_id, "exp": datetime.now(timezone.utc).timestamp() + 86400}  # 24 hours
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("user_id")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        user_data = await db.users.find_one({"id": user_id})
        if not user_data:
            raise HTTPException(status_code=401, detail="User not found")
        
        return User(**user_data)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# User Service Routes
@api_router.post("/users/register", response_model=UserResponse)
async def register_user(user_data: UserCreate):
    # Check if user already exists
    existing_user = await db.users.find_one({"email": user_data.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Hash password and create user
    hashed_password = hash_password(user_data.password)
    user = User(
        email=user_data.email,
        first_name=user_data.first_name,
        last_name=user_data.last_name
    )
    
    user_dict = user.dict()
    user_dict["password"] = hashed_password
    await db.users.insert_one(user_dict)
    
    # Create JWT token
    token = create_jwt_token(user.id)
    
    return UserResponse(user=user, token=token)

@api_router.post("/users/login", response_model=UserResponse)
async def login_user(login_data: UserLogin):
    # Find user
    user_data = await db.users.find_one({"email": login_data.email})
    if not user_data or not verify_password(login_data.password, user_data["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    user = User(**user_data)
    token = create_jwt_token(user.id)
    
    return UserResponse(user=user, token=token)

@api_router.get("/users/profile", response_model=User)
async def get_profile(current_user: User = Depends(get_current_user)):
    return current_user

# Product Service Routes
@api_router.get("/products", response_model=List[Product])
async def get_products(category: Optional[str] = None, search: Optional[str] = None):
    query = {}
    if category:
        query["category"] = category
    if search:
        query["$or"] = [
            {"name": {"$regex": search, "$options": "i"}},
            {"description": {"$regex": search, "$options": "i"}}
        ]
    
    products = await db.products.find(query).to_list(100)
    return [Product(**product) for product in products]

@api_router.get("/products/{product_id}", response_model=Product)
async def get_product(product_id: str):
    product = await db.products.find_one({"id": product_id})
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    return Product(**product)

@api_router.post("/products", response_model=Product)
async def create_product(product_data: ProductCreate):
    product = Product(**product_data.dict())
    await db.products.insert_one(product.dict())
    return product

# Cart Service Routes
@api_router.get("/cart", response_model=Cart)
async def get_cart(current_user: User = Depends(get_current_user)):
    cart_data = await db.carts.find_one({"user_id": current_user.id})
    if not cart_data:
        # Create empty cart
        cart = Cart(user_id=current_user.id)
        await db.carts.insert_one(cart.dict())
        return cart
    return Cart(**cart_data)

@api_router.post("/cart/add")
async def add_to_cart(item: AddToCartRequest, current_user: User = Depends(get_current_user)):
    # Get product details
    product = await db.products.find_one({"id": item.product_id})
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    
    # Get or create cart
    cart_data = await db.carts.find_one({"user_id": current_user.id})
    if not cart_data:
        cart = Cart(user_id=current_user.id)
    else:
        cart = Cart(**cart_data)
    
    # Check if item already in cart
    existing_item = None
    for cart_item in cart.items:
        if cart_item.product_id == item.product_id:
            existing_item = cart_item
            break
    
    if existing_item:
        existing_item.quantity += item.quantity
    else:
        cart_item = CartItem(
            product_id=item.product_id,
            quantity=item.quantity,
            price=product["price"]
        )
        cart.items.append(cart_item)
    
    # Calculate total
    cart.total = sum(item.price * item.quantity for item in cart.items)
    cart.updated_at = datetime.now(timezone.utc)
    
    # Update in database
    await db.carts.replace_one({"user_id": current_user.id}, cart.dict(), upsert=True)
    
    return {"message": "Item added to cart"}

@api_router.delete("/cart/remove/{product_id}")
async def remove_from_cart(product_id: str, current_user: User = Depends(get_current_user)):
    cart_data = await db.carts.find_one({"user_id": current_user.id})
    if not cart_data:
        raise HTTPException(status_code=404, detail="Cart not found")
    
    cart = Cart(**cart_data)
    cart.items = [item for item in cart.items if item.product_id != product_id]
    cart.total = sum(item.price * item.quantity for item in cart.items)
    cart.updated_at = datetime.now(timezone.utc)
    
    await db.carts.replace_one({"user_id": current_user.id}, cart.dict())
    return {"message": "Item removed from cart"}

# Order Service Routes
@api_router.post("/orders", response_model=Order)
async def create_order(order_data: OrderCreate, current_user: User = Depends(get_current_user)):
    # Get cart
    cart_data = await db.carts.find_one({"user_id": current_user.id})
    if not cart_data or not cart_data["items"]:
        raise HTTPException(status_code=400, detail="Cart is empty")
    
    cart = Cart(**cart_data)
    
    # Create order items
    order_items = []
    for cart_item in cart.items:
        product = await db.products.find_one({"id": cart_item.product_id})
        if product:
            order_item = OrderItem(
                product_id=cart_item.product_id,
                product_name=product["name"],
                quantity=cart_item.quantity,
                price=cart_item.price
            )
            order_items.append(order_item)
    
    # Create order
    order = Order(
        user_id=current_user.id,
        items=order_items,
        total=cart.total,
        shipping_address=order_data.shipping_address
    )
    
    await db.orders.insert_one(order.dict())
    
    # Clear cart
    await db.carts.delete_one({"user_id": current_user.id})
    
    return order

@api_router.get("/orders", response_model=List[Order])
async def get_orders(current_user: User = Depends(get_current_user)):
    orders = await db.orders.find({"user_id": current_user.id}).to_list(100)
    return [Order(**order) for order in orders]

@api_router.get("/orders/{order_id}", response_model=Order)
async def get_order(order_id: str, current_user: User = Depends(get_current_user)):
    order = await db.orders.find_one({"id": order_id, "user_id": current_user.id})
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    return Order(**order)

# Payment Service Routes
@api_router.post("/payments/{order_id}", response_model=Payment)
async def process_payment(order_id: str, current_user: User = Depends(get_current_user)):
    # Get order
    order = await db.orders.find_one({"id": order_id, "user_id": current_user.id})
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    
    # Mock payment processing
    payment = Payment(
        order_id=order_id,
        amount=order["total"],
        status="completed"  # Mock successful payment
    )
    
    await db.payments.insert_one(payment.dict())
    
    # Update order status
    await db.orders.update_one(
        {"id": order_id},
        {"$set": {"status": "paid"}}
    )
    
    return payment

# Initialize sample products
@api_router.post("/admin/init-products")
async def initialize_sample_products():
    # Check if products already exist
    existing_products = await db.products.count_documents({})
    if existing_products > 0:
        return {"message": "Products already initialized"}
    
    sample_products = [
        {
            "name": "Premium Dental Care Set",
            "description": "Complete oral care solution with professional-grade toothpaste and accessories",
            "price": 29.99,
            "image_url": "https://images.unsplash.com/photo-1691096673040-1632eb4b0a9d?crop=entropy&cs=srgb&fm=jpg&ixid=M3w3NTY2NzB8MHwxfHNlYXJjaHwxfHxlY29tbWVyY2UlMjBwcm9kdWN0c3xlbnwwfHx8fDE3NTc4OTg1Mjd8MA&ixlib=rb-4.1.0&q=85",
            "category": "Health & Beauty",
            "stock": 50
        },
        {
            "name": "Professional Toothpaste Duo",
            "description": "Twin pack of premium fluoride toothpaste for complete dental protection",
            "price": 19.99,
            "image_url": "https://images.unsplash.com/photo-1691096673789-ae6a7492fd97?crop=entropy&cs=srgb&fm=jpg&ixid=M3w3NTY2NzB8MHwxfHNlYXJjaHwyfHxlY29tbWVyY2UlMjBwcm9kdWN0c3xlbnwwfHx8fDE3NTc4OTg1Mjd8MA&ixlib=rb-4.1.0&q=85",
            "category": "Health & Beauty",
            "stock": 75
        },
        {
            "name": "Lifestyle Essentials Bundle",
            "description": "Curated collection of daily essentials and wellness products",
            "price": 89.99,
            "image_url": "https://images.unsplash.com/photo-1691096674326-74cfe19c04cc?crop=entropy&cs=srgb&fm=jpg&ixid=M3w3NTY2NzB8MHwxfHNlYXJjaHwzfHxlY29tbWVyY2UlMjBwcm9kdWN0c3xlbnwwfHx8fDE3NTc4OTg1Mjd8MA&ixlib=rb-4.1.0&q=85",
            "category": "Lifestyle",
            "stock": 30
        },
        {
            "name": "Complete Oral Health Kit",
            "description": "Professional dental care system with advanced whitening formula",
            "price": 45.99,
            "image_url": "https://images.unsplash.com/photo-1691096674749-29069acd529c?crop=entropy&cs=srgb&fm=jpg&ixid=M3w3NTY2NzB8MHwxfHNlYXJjaHw0fHxlY29tbWVyY2UlMjBwcm9kdWN0c3xlbnwwfHx8fDE3NTc4OTg1Mjd8MA&ixlib=rb-4.1.0&q=85",
            "category": "Health & Beauty",
            "stock": 40
        },
        {
            "name": "Glossier Beauty Collection",
            "description": "Premium cosmetics and skincare products for modern beauty routines",
            "price": 125.00,
            "image_url": "https://images.unsplash.com/photo-1629198688000-71f23e745b6e?crop=entropy&cs=srgb&fm=jpg&ixid=M3w3NDQ2NDF8MHwxfHNlYXJjaHwxfHxwcm9kdWN0c3xlbnwwfHx8fDE3NTc4OTg1MzJ8MA&ixlib=rb-4.1.0&q=85",
            "category": "Beauty",
            "stock": 25
        },
        {
            "name": "Nike Air Performance Sneaker",
            "description": "High-performance athletic footwear with advanced cushioning technology",
            "price": 159.99,
            "image_url": "https://images.unsplash.com/photo-1542291026-7eec264c27ff?crop=entropy&cs=srgb&fm=jpg&ixid=M3w3NDQ2NDF8MHwxfHNlYXJjaHwyfHxwcm9kdWN0c3xlbnwwfHx8fDE3NTc4OTg1MzJ8MA&ixlib=rb-4.1.0&q=85",
            "category": "Fashion",
            "stock": 60
        },
        {
            "name": "Curology Skincare System",
            "description": "Personalized skincare solution with custom formulated treatments",
            "price": 79.99,
            "image_url": "https://images.unsplash.com/photo-1571781926291-c477ebfd024b?crop=entropy&cs=srgb&fm=jpg&ixid=M3w3NDQ2NDF8MHwxfHNlYXJjaHwzfHxwcm9kdWN0c3xlbnwwfHx8fDE3NTc4OTg1MzJ8MA&ixlib=rb-4.1.0&q=85",
            "category": "Skincare",
            "stock": 35
        },
        {
            "name": "Minimalist Bottle Collection",
            "description": "Elegant glass bottles perfect for storage and home organization",
            "price": 39.99,
            "image_url": "https://images.unsplash.com/photo-1611930022073-b7a4ba5fcccd?crop=entropy&cs=srgb&fm=jpg&ixid=M3w3NDQ2NDF8MHwxfHNlYXJjaHw0fHxwcm9kdWN0c3xlbnwwfHx8fDE3NTc4OTg1MzJ8MA&ixlib=rb-4.1.0&q=85",
            "category": "Home & Living",
            "stock": 20
        }
    ]
    
    products = [Product(**product_data) for product_data in sample_products]
    await db.products.insert_many([product.dict() for product in products])
    
    return {"message": f"Initialized {len(products)} sample products"}

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()