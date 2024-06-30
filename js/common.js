document.addEventListener("DOMContentLoaded", function() {
  'use strict';

  const body = document.querySelector("body"),
  menuOpenIcon = document.querySelector(".nav__icon-menu"),
  menuCloseIcon = document.querySelector(".nav__icon-close"),
  menuList = document.querySelector(".menu-overlay"),
  searchOpenIcon = document.querySelector(".search-button"),
  searchCloseIcon = document.querySelector(".search__close"),
  searchInput = document.querySelector(".search__text"),
  search = document.querySelector(".search"),
  btnScrollToTop = document.querySelector(".top");


  /* =======================
  // Menu and Search
  ======================= */
  menuOpenIcon.addEventListener("click", () => {
    menuOpen();
  });

  menuCloseIcon.addEventListener("click", () => {
    menuClose();
  });

  searchOpenIcon.addEventListener("click", () => {
    searchOpen();
  });

  searchCloseIcon.addEventListener("click", () => {
    searchClose();
  });

  function menuOpen() {
    menuList.classList.add("is-open");
  }

  function menuClose() {
    menuList.classList.remove("is-open");
  }

  function searchOpen() {
    search.classList.add("is-visible");
    setTimeout(function () {
      searchInput.focus();
    }, 300);
  }

  function searchClose() {
    search.classList.remove("is-visible");
  }

  document.addEventListener("keydown", function(e){
    if (e.key == "Escape") {
      searchClose();
    }
  });


  /* =======================
  // Animation Load Page
  ======================= */
  setTimeout(function(){
    body.classList.add("is-in");
  },150)


  /* =======================
  // LazyLoad Images
  ======================= */
  var lazyLoadInstance = new LazyLoad({
    elements_selector: '.lazy'
  })


  /* =======================
  // Zoom Image
  ======================= */
  const lightense = document.querySelector(".page img, .post img"),
  imageLink = document.querySelectorAll(".page a img, .post a img");

  if (imageLink) {
    for (let i = 0; i < imageLink.length; i++) imageLink[i].parentNode.classList.add("image-link");
    for (let i = 0; i < imageLink.length; i++) imageLink[i].classList.add("no-lightense");
  };

  if (lightense) {
    Lightense(".page img:not(.no-lightense), .post img:not(.no-lightense)", {
    padding: 60,
    offset: 30
    });
  };


  /* =======================
  // Responsive Videos
  ======================= */
  reframe(".post__content iframe:not(.reframe-off), .page__content iframe:not(.reframe-off)");


  // =====================
  // Load More Posts
  // =====================
  var load_posts_button = document.querySelector('.load-more-posts');

  load_posts_button&&load_posts_button.addEventListener("click",function(e){e.preventDefault();var o=document.querySelector(".load-more-section"),e=pagination_next_url.split("/page")[0]+"/page/"+pagination_next_page_number+"/";fetch(e).then(function(e){if(e.ok)return e.text()}).then(function(e){var n=document.createElement("div");n.innerHTML=e;for(var t=document.querySelector(".grid"),a=n.querySelectorAll(".grid__post"),i=0;i<a.length;i++)t.appendChild(a.item(i));new LazyLoad({elements_selector:".lazy"});pagination_next_page_number++,pagination_next_page_number>pagination_available_pages_number&&(o.style.display="none")})});


  /* =======================
  // Scroll Top Button
  ======================= */
  window.addEventListener("scroll", function () {
  window.scrollY > window.innerHeight ? btnScrollToTop.classList.add("is-active") : btnScrollToTop.classList.remove("is-active");
  });

  btnScrollToTop.addEventListener("click", function () {
    if (window.scrollY != 0) {
      window.scrollTo({
        top: 0,
        left: 0,
        behavior: "smooth"
      })
    }
  });

});