# -*- coding: utf-8 -*-

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify

from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from database_setup import Base, Category, Item, User

from flask import session as login_session
import random
import string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

engine = create_engine('sqlite:///accessories_store.db', connect_args={'check_same_thread': False})
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(52))
    login_session['state'] = state
    return render_template('login.htm', STATE=state)

@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    # login com o facebook
    
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print("access token received %s " % access_token)


    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]


    # Token para pegar informações da API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = 'https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    login_session['access_token'] = token

    url = 'https://graph.facebook.com/v2.8/me/picture?access_token=%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]


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
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output

@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id,access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"

@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validando o estado do token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtem o código de autorização
    code = request.data

    try:
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Checa se o acesso do token é válido
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print("done!")
    return output

@app.route('/gdisconnect')
def gdisconnect():
        # Disconecta um usuário já conectado
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        # Reseta a sessão de usuário.
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']

        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        # Se por alguma razão o token de acesso for invalido
        response = make_response(
        json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response

def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

@app.route('/categories/<int:category_id>/menu/JSON')
def categoriesMenuJSON(category_id):
    categories = session.query(Category).filter_by(id=category_id).one()
    items = session.query(Item).filter_by(
        restaurant_id=category_id).all()
    return jsonify(MenuItems=[i.serialize for i in items])


@app.route('/categories/<int:category_id>/menu/<int:items_id>/JSON')
def ItemJSON(category_id, items_id):
    Menu_Item = session.query(Item).filter_by(id=items_id).one()
    return jsonify(Menu_Item=Menu_Item.serialize)


@app.route('/categories/JSON')
def categoriesJSON():
    categorys = session.query(Category).all()
    return jsonify(categories=[r.serialize for r in categorys])

@app.route('/categories/menu')
def showCategories():
    categories = session.query(Category).all()
    if 'username' not in login_session:
        return render_template('publicrestaurants.htm', categories = categories)
    # Página Inicial com os nomes dos Restaurantes
    else:
        return render_template('category_all.htm', categories=categories)

@app.route('/categories/new', methods=['GET', 'POST'])
def newCategory():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        addCategory = Category(name=request.form['name'], description=request.form['description'],
            user_id=login_session['user_id'])
        session.add(addCategory)
        session.commit()
        flash("new Category was created!")
        # Página para criar um novo Restaurante
        return redirect(url_for('showCategories'))
    else:
        return render_template('new_category.htm')

@app.route('/categories/<int:category_id>/delete/', methods=['GET', 'POST'])
def deleteCategory(category_id):
    if 'username' not in login_session:
        return redirect('/login')
    itemToDelete = session.query(Category).filter_by(id = category_id).one()
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash("Menu Item has been deleted")
        return redirect(url_for('showCategories'))
    else:
        return render_template('delete_category.htm', item=itemToDelete, category_id = category_id)

@app.route('/categories/<int:category_id>/edit/', methods=['GET', 'POST'] )
def editCategory(category_id):
    if 'username' not in login_session:
        return redirect('/login')
    editedCategory = session.query(Category).filter_by(id=category_id).one()
    if request.method == 'POST':
        if request.form['name']:
            editedCategory.name = request.form['name']
            editedCategory.description = request.form['description']
        session.add(editedCategory)
        session.commit()
        flash("Menu Item has been edited")
        return redirect(url_for('showCategories'))
    else:
        return render_template(
            'edit_category.htm', category_id=category_id, item=editedCategory)
    #Página para editar a categoria

@app.route('/categories/<int:category_id>/menu')
@app.route('/categories/<int:category_id>/')
def showMenu(category_id):
    #Página com o cardápio da Categoria selecionada
    categories = session.query(Category).filter_by(id=category_id).one()
    creator = getUserInfo(categories.user_id)
    items = session.query(Item).filter_by(category_id=category_id).all()
    if 'username' not in login_session or creator.id != login_session['user_id']:
        return render_template('publicmenu.htm', items = items, categories = categories, creator = creator)
    else:
        return render_template(
            'menu_items.htm', categories=categories, items=items, category_id=category_id)

@app.route('/categories/<int:category_id>/<int:items_id>/new', methods=['GET', 'POST'])
def newMenuItem(category_id, items_id):
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newItem = Item(name=request.form['name'], description=request.form[
                           'description'], price=request.form['price'], course=request.form['course'],
                            user_id=Category.user_id, category_id=category_id)
        session.add(newItem)
        session.commit()
        flash("new menu item created!")
        return redirect(url_for('showMenu', category_id=category_id, items_id = items_id))
    else:
        return render_template('add_items.htm', category_id=category_id, items_id = items_id)

    #Página para criar um novo item para a categoria
    return render_template('add_items.htm', category_id = category_id, items_id = items_id, item = newItem)

@app.route('/categories/<int:category_id>/menu/<int:items_id>/edit', methods=['GET', 'POST'])
def editMenuItem(category_id, items_id):
    if 'username' not in login_session:
        return redirect('/login')
    editedItem = session.query(Item).filter_by(id=items_id).one()
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        session.add(editedItem)
        session.commit()
        flash("Menu Item has been edited")
        return redirect(url_for('showMenu', category_id=category_id, items_id = items_id))
    else:
            return render_template(
                'edit_item.htm', category_id=category_id, items_id=items_id, item=editedItem)
    #Página para editar um item selecionado

@app.route('/restaurants/<int:category_id>/menu/<int:items_id>/delete', methods=['GET', 'POST'])
def deleteMenuItem(category_id, items_id):
    if 'username' not in login_session:
        return redirect('/login')
    itemToDelete = session.query(Item).filter_by(id=items_id).one()
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash("Menu Item has been deleted")
        return redirect(url_for('showMenu', category_id=category_id, items_id = items_id))
    else:
        return render_template('delete_item.htm', category_id = category_id, item=itemToDelete, items_id = items_id)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True        
    app.run(host='0.0.0.0', port=5000)
