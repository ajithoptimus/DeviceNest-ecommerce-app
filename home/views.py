from django.shortcuts import render

# Create your views here.

def home(request):
    return render(request, 'home/home.html')

def cart(request):
    return render(request, 'cart/cart.html')
