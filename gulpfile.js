const gulp = require('gulp');
const sass = require('gulp-sass')(require('sass'));
const sourcemaps = require('gulp-sourcemaps');
const rename = require("gulp-rename");
const {parallel} = require('gulp');
const coffee = require('gulp-coffee');

const config = {
    srcCss: ['./apps/client/static/scss/main.scss'], buildCss: './apps/client/static/css'
};

function buildStyles() {
    return gulp.src(config.srcCss)
        .pipe(sourcemaps.init())
        .pipe(sass().on('error', sass.logError))
        .pipe(sourcemaps.write('.'))
        .pipe(gulp.dest(config.buildCss))
}

function buildMinStyles() {
    return gulp.src(config.srcCss)
        .pipe(sass({outputStyle: 'compressed'}).on('error', sass.logError))
        .pipe(rename({extname: '.min.css'}))
        .pipe(gulp.dest(config.buildCss))
}

function copyJavaScriptFiles() {
    return gulp.src([
        './node_modules/bootstrap/dist/js/bootstrap.bundle.min.js',
        './node_modules/jquery/dist/jquery.min.js'])
        .pipe(gulp.dest('./apps/client/static/js/vendor'))
}

function copyFontFiles() {
    return gulp.src([
        './node_modules/bootstrap-icons/font/*.css',
        './node_modules/bootstrap-icons/font/**//fonts/*.*',
    ]).pipe(gulp.dest('./apps/client/static/font'))
}

function compileCoffee() {
    return gulp.src('./apps/client/static/js/*.coffee')
        .pipe(sourcemaps.init())
        .pipe(coffee())
        .pipe(sourcemaps.write('.'))
        .pipe(gulp.dest('./apps/client/static/js'));
}

exports.default = parallel(buildStyles, buildMinStyles, copyJavaScriptFiles, copyFontFiles, compileCoffee);
