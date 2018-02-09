import React from 'react';
import ReactDOM from 'react-dom';
import { HashRouter, Switch, Route } from 'react-router-dom';
import 'semantic-ui-css/semantic.min.css';
import './index.css';
import App from './App';
import registerServiceWorker from './registerServiceWorker';


ReactDOM.render(
    <HashRouter>
        <Switch>
            <Route path="/func/:funcName" component={App} />
            <Route component={App} />
        </Switch>
    </HashRouter>,
    document.getElementById('root'));

registerServiceWorker();
