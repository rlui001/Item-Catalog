from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
app = Flask(__name__)

from sqlalchemy import create_engine
from sqlalchemy. orm import sessionmaker
from database_setup import Base, Restaurant, MenuItem, User

#NEW IMPORTS FOR OAUTH2.0
#Import as login_session because session is used by sqlite
from flask import session as login_session
import random, string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

CLIENT_ID = json.loads(
	open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Restaurant Menu Application"

engine = create_engine('sqlite:///restaurantmenuwithusers.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

#Create a state token to prevent request forgery
#Store it in the session for later validation
@app.route('/login')
def showLogin():
	"""Creates client token to prevent outside parties from accessing login. Redirects to login page."""
	state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
	login_session['state'] = state
	return render_template('login.html', STATE = state)

@app.route('/gconnect', methods=['POST'])
def gconnect():
	"""This method deals with log in authentication and oauth for google plus."""
	# Validate state token
	if request.args.get('state') != login_session['state']:
		response = make_response(json.dumps('Invalid state'), 401)
		response.headers['Content-Type'] = 'application/json'
		return response
	# Obtain authorization code
	code = request.data
	try:
		# upgrade the authorization code into a credentials object
		oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
		oauth_flow.redirect_uri = 'postmessage'
		credentials = oauth_flow.step2_exchange(code)
	except FlowExchangeError:
		response = make_response(json.dumps('Failed to upgrade the authorization code.'), 401)
		response.headers['Content-Type'] = 'application/json'
		return response
	# check access token is valid
	access_token = credentials.access_token
	url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)
	h = httplib2.Http()
	result = json.loads(h.request(url, 'GET')[1])
	# If there was an error in the access token info, abort.
	if result.get('error') is not None:
		response = make_response(json.dumps(result.get('error')), 501)
		response.headers['Content-Type'] = 'application/json'
		return response
	# Verify that the access token is used for the intended user.
	gplus_id = credentials.id_token['sub']
	if result['user_id'] != gplus_id:
		response = make_response(
			json.dumps("Token's user ID doesn't match given user ID."), 401)
		response.headers['Content-Type'] = 'application/json'
		return response
	# Verify that the access token is valid for this app
	if result['issued_to'] != CLIENT_ID:
		response = make_response(
			json.dumps("Token's client ID does not match app's."), 401)
		print "Token's client ID does not match app's."
		response.headers['Content-Type'] = 'application/json'
		return response
	# Check to see if user is already logged in
	stored_access_token = login_session.get('access_token')
	stored_gplus_id = login_session.get('gplus_id')
	if stored_access_token is not None and gplus_id == stored_gplus_id:
		response = make_response(json.dumps('Current user is already connected.'),200)
		response.headers['Content-Type'] = 'application/json'
		return response
	# Store the access token in the session for later use
	login_session['access_token'] = credentials.access_token
	login_session['gplus_id'] = gplus_id

	# Get user info
	userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
	params = {'access_token': credentials.access_token, 'alt':'json'}
	answer = requests.get(userinfo_url, params=params)
	data = json.loads(answer.text)

	login_session['username'] = data["name"]
	login_session['picture'] = data["picture"]
	login_session['email'] = data["email"]
	login_session['provider'] = 'google'

	# see if user exists. if not, make a new one
	user_id = getUserID(login_session['email'])
	if not user_id:
		user_id = createUser(login_session)
	login_session['user_id'] = user_id

	output = ''
	output += '<h1>Welcome, '
	output += login_session['username']

	output += '!</h1>'
	output += '<img src="'
	output += login_session['picture']
	output += ' "style = width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
	flash("you are now logged in as %s" % login_session['username'])
	return output

#DISCONNECT - revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
	"""This method handles logout/disconnect for users via google log in."""
	access_token = login_session['access_token']
	if access_token is None:
		response = make_response(json.dumps('Current user not connected.'), 401)
		response.headers['Content-Type'] = 'application/json'
		return response
	url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
	h = httplib2.Http()
	result = h.request(url, 'GET')[0]
	if result['status'] == '200':
		response = make_response(json.dumps('Successfully disconnected.'), 200)
		response.headers['Content-Type'] = 'application/json'
		return response
	else:
	
		response = make_response(json.dumps('Failed to revoke token for given user.', 400))
		response.headers['Content-Type'] = 'application/json'
		return response

@app.route('/fbconnect', methods=['POST'])
def fbconnect():
	"""This method deals with login authentication/oauth via facebook login."""
	if request.args.get('state') != login_session ['state']:
		response = make_response(json.dumps('Invalid state parameter.'), 401)
		response.headers['Content-Type'] = 'application/json'
		return response
	access_token = request.data
	print "access token received %s" % access_token


	#Exchange client token for long-lived server-side token 
	app_id = json.loads(open('fb_client_secrets.json', 'r').read())['web']['app_id']
	app_secret = json.loads(open('fb_client_secrets.json', 'r').read())['web']['app_secret']
	url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (app_id, app_secret, access_token)
	h = httplib2.Http()
	result = h.request(url, 'GET')[1]

	#Use token to get user info from API
	userinfo_url = "https://graph.facebook.com/v2.2/me"
	#strip expire tag from access token
	token = result.split("&")[0]

	url = 'https://graph.facebook.com/v2.4/me?%s&fields=name,id,email' % token
	h = httplib2.Http()
	result = h.request(url, 'GET')[1]
	
	data = json.loads(result)
	login_session['provider'] = 'facebook'
	login_session['username'] = data["name"]
	login_session['email'] = data["email"]
	login_session['facebook_id'] = data["id"]

	# token must be stored to properly log out
	stored_token = token.split("=")[1]
	login_session['access_token'] = stored_token

	#Get user picture
	url = 'https://graph.facebook.com/v2.2/me/picture?%s&redirect=0&height=200&width=200' % token
	h = httplib2.Http()
	result = h.request(url, 'GET')[1]
	data = json.loads(result)

	login_session['picture'] = data["data"]["url"]

	#see if user exists
	user_id = getUserID(login_session['email'])
	if not user_id:
		user_id = createUser(login_session)
	login_session['user_id'] = user_id

	output = ''
	output += '<h1>Welcome, '
	output += login_session['username']

	output += '!</h1>'
	output += '<img src="'
	output += login_session['picture']
	output += ' "style = width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
	flash("you are now logged in as %s" % login_session['username'])
	return output

@app.route('/fbdisconnect')
def fbdisconnect():
	"""This method deals with logout/disconnect for users that logged in via facebook."""
	facebook_id = login_session['facebook_id']
	access_token = login_session['access_token']
	url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id,access_token)
	h = httplib2.Http()
	result = h.request(url, 'DELETE')[1]
	return "you have been logged out"

#Disconnect based on provider
@app.route('/disconnect')
def disconnect():
	"""Handles user disconnect, redirects to proper disconnect method based on login provider."""
	if 'provider' in login_session:
		if login_session['provider'] == 'google':
			gdisconnect()
			del login_session['gplus_id']
			del login_session['credentials']
		if login_session['provider'] == 'facebook':
			fbdisconnect()
			del login_session['facebook_id']

		del login_session['username']
		del login_session['email']
		del login_session['picture']
		del login_session['user_id']
		del login_session['provider']
		flash("You have successfully logged out.")
		return redirect(url_for('showRestaurants'))
	else:
		flash("YOu were not logged in")
		return redirect(url_for('showRestaurants'))



#Making an API Endpoint (GET Request)
@app.route('/restaurants/JSON')
def restaurantJSON():
	"""JSON endpoint for restaurant objects."""
	restaurants = session.query(Restaurant).all()
	return jsonify(Restaurants=[r.serialize for r in restaurants])


@app.route('/restaurants/<int:restaurant_id>/menu/JSON')
def restaurantMenuJSON(restaurant_id):
	"""JSON endpoint for menu objects for a restaurant."""
	restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
	items = session.query(MenuItem).filter_by(restaurant_id = restaurant_id).all()
	return jsonify(MenuItems=[i.serialize for i in items])

@app.route('/restaurants/<int:restaurant_id>/menu/<int:menu_id>/JSON')
def singleMenuItemJSON(restaurant_id, menu_id):
	"""JSON endpoint for a single menu object."""
	menu_item = session.query(MenuItem).filter_by(id = menu_id).one()
	return jsonify(MenuItem=[menu_item.serialize])

# Routes to pages for users

# Restaurant stuff
@app.route('/')
@app.route('/restaurants/')
def showRestaurants():
	"""Displays the proper restaurant list based on user's authorization."""
	restaurants = session.query(Restaurant).all()
	if 'username' not in login_session:
		return render_template('publicrestaurants.html', restaurants = restaurants)
	else:
		return render_template('restaurants.html', restaurants = restaurants)

@app.route('/restaurants/new', methods=['GET','POST'])
def newRestaurant():
	"""Creates a new restaurant."""
	if 'username' not in login_session:
		return redirect('/login')
	if request.method=='POST':
		createRestaurant = Restaurant(name = request.form['name'], user_id=login_session['user_id'])
		session.add(createRestaurant)
		session.commit()
		flash("New restaurant added!")
		return redirect(url_for('showRestaurants'))
	else:
		return render_template('newRestaurant.html')

@app.route('/restaurants/<int:restaurant_id>/edit', methods=['GET','POST'])
def editRestaurant(restaurant_id):
	"""Edits a restaurant."""
	if 'username' not in login_session:
		return redirect('/login')
	editedRestaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
	if editedRestaurant.user_id != login_session['user_id']:
		return "<script>function myFunction() {alert('You are not authorized to edit this restaurant. Please create your own restaurant in order to edit.');}</script><body onload='myFunction()''>"
	if request.method=='POST':
		if request.form['name']:
			editedRestaurant.name = request.form['name']
		session.add(editedRestaurant)
		session.commit()
		flash("Restaurant edited!")
		return redirect(url_for('showRestaurants'))
	else:	
		return render_template('editRestaurant.html', restaurant_id = restaurant_id, r = editedRestaurant)

@app.route('/restaurants/<int:restaurant_id>/delete', methods=['GET','POST'])
def deleteRestaurant(restaurant_id): 
	"""Deletes a restaurant."""
	if 'username' not in login_session:
		return redirect('/login')
	deleteRestaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
	if deleteRestaurant.user_id != login_session['user_id']:
		return "<script>function myFunction() {alert('You are not authorized to delete this restaurant. Please create your own restaurant in order to delete.');}</script><body onload='myFunction()''>"
	if request.method == 'POST':
		session.delete(deleteRestaurant)
		session.commit()
		flash("Restaurant deleted!")
		return redirect(url_for('showRestaurants'))
	else:
		return render_template('deleteRestaurant.html', r = deleteRestaurant)

#Menu stuff

@app.route('/restaurants/<int:restaurant_id>/')
@app.route('/restaurants/<int:restaurant_id>/menu/')
def restaurantMenu(restaurant_id):
	"""Displays menu for restaurant, based on authorization."""
	restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
	items = session.query(MenuItem).filter_by(restaurant_id = restaurant_id)
	creator = getUserInfo(restaurant.user_id)
	if 'username' not in login_session or creator.id != login_session['user_id']:
		return render_template('publicmenu.html', restaurant = restaurant, items = items, creator = creator)
	else:
		return render_template('menu.html', restaurant = restaurant, items = items, creator = creator)

# Create route for newMenuItem function 
@app.route('/restaurants/<int:restaurant_id>/new', methods=['GET','POST'])
def newMenuItem(restaurant_id):
	"""Create a new menu item."""
	if 'username' not in login_session:
		return redirect('/login')
	restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
	if restaurant.user_id != login_session['user_id']:
		return "<script>function myFunction() {alert('You are not authorized to add menu items to this restaurant. Please create your own restaurant in order to add items.');}</script><body onload='myFunction()''>"
	if request.method=='POST':
		# possible bug here, does not handle empty input
		newItem = MenuItem(name = request.form['name'],restaurant_id = restaurant_id, description = request.form['description'], course = request.form['course'], price = request.form['price'], user_id=restaurant.user_id)
		session.add(newItem)
		session.commit()
		flash("New menu item created!")
		return redirect(url_for('restaurantMenu', restaurant_id = restaurant_id))
	else:
		return render_template('newmenuitem.html', restaurant_id = restaurant_id)

# Create route for editMenuItem function 
@app.route('/restaurants/<int:restaurant_id>/<int:menu_id>/edit', methods=['GET','POST'])
def editMenuItem(restaurant_id, menu_id):
	"""Edits a menu item."""
	editedItem = session.query(MenuItem).filter_by(id = menu_id).one()
	if 'username' not in login_session:
		return redirect('/login')
	restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
	if restaurant.user_id != login_session['user_id']:
		return "<script>function myFunction() {alert('You are not authorized to edit menu items to this restaurant. Please create your own restaurant in order to edit items.');}</script><body onload='myFunction()''>"
	if request.method == 'POST':
		if request.form['name']:
			editedItem.name = request.form['name']
		if request.form['price']:
			editedItem.price = request.form['price']
		if request.form['description']:
			editedItem.description = request.form['description']
		editedItem.course = request.form['course']
		session.add(editedItem)
		session.commit()
		flash("Menu item edited!")
		return redirect(url_for('restaurantMenu', restaurant_id = restaurant_id))
	else:
		return render_template('editmenuitem.html', restaurant_id = restaurant_id, menu_id = menu_id, i = editedItem)

#Task 3: Create a route for deleteMenuItem function 
@app.route('/restaurants/<int:restaurant_id>/<int:menu_id>/delete', methods=['GET','POST'])
def deleteMenuItem(restaurant_id, menu_id):
	"""Deletes a menu item."""
	if 'username' not in login_session:
		return redirect('/login')
	deleteItem = session.query(MenuItem).filter_by(id = menu_id).one()
	restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
	if restaurant.user_id != login_session['user_id']:
		return "<script>function myFunction() {alert('You are not authorized to delete menu items to this restaurant. Please create your own restaurant in order to delete items.');}</script><body onload='myFunction()''>"
	if request.method == 'POST':
		session.delete(deleteItem)
		session.commit()
		flash("Menu item deleted!")
		return redirect(url_for('restaurantMenu', restaurant_id = restaurant_id))
	else:
		return render_template('deletemenuitem.html', i = deleteItem)

# Methods that deal with creating local user/accessing local user info

def getUserID(email):
	"""Acquires the user ID currently logged in."""
	try:
		user = session.query(User).filter_by(email = email).one()
		return user.id
	except:
		return None

def getUserInfo(user_id):
	"""Acquires the user's info."""
	user = session.query(User).filter_by(id = user_id).one()
	return user

def createUser(login_session):
	"""Creates a local user based on the information obtained from google/facebook user login."""
	newUser = User(name=login_session['username'], email=login_session['email'], picture=login_session['picture'])
	session.add(newUser)
	session.commit()
	user = session.query(User).filter_by(email=login_session['email']).one()
	return user.id


if __name__ == '__main__':
	app.secret_key = 'super_secret_key'
	app.debug = True
	app.run(host = '0.0.0.0', port = 5000)